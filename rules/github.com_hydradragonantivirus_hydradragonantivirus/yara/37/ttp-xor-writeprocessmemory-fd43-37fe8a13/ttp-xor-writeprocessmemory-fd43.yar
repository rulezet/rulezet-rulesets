rule TTP_XOR_WriteProcessMemory_fd43 {
  strings:
    $key_fd43 = { aa 31 [2] 98 13 [2] 9e 26 [2] b0 26 [2] 8f 3a }

  condition:
    any of them
}