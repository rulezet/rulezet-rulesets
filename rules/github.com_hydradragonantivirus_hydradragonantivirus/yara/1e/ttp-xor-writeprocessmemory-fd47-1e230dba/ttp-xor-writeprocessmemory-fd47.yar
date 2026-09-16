rule TTP_XOR_WriteProcessMemory_fd47 {
  strings:
    $key_fd47 = { aa 35 [2] 98 17 [2] 9e 22 [2] b0 22 [2] 8f 3e }

  condition:
    any of them
}