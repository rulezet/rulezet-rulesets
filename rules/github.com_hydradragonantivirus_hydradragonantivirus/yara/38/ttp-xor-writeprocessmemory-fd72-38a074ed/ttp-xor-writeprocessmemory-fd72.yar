rule TTP_XOR_WriteProcessMemory_fd72 {
  strings:
    $key_fd72 = { aa 00 [2] 98 22 [2] 9e 17 [2] b0 17 [2] 8f 0b }

  condition:
    any of them
}