rule TTP_XOR_WriteProcessMemory_fd03 {
  strings:
    $key_fd03 = { aa 71 [2] 98 53 [2] 9e 66 [2] b0 66 [2] 8f 7a }

  condition:
    any of them
}