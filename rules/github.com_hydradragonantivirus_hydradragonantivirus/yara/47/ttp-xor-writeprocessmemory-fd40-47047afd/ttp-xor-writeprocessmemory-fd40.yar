rule TTP_XOR_WriteProcessMemory_fd40 {
  strings:
    $key_fd40 = { aa 32 [2] 98 10 [2] 9e 25 [2] b0 25 [2] 8f 39 }

  condition:
    any of them
}