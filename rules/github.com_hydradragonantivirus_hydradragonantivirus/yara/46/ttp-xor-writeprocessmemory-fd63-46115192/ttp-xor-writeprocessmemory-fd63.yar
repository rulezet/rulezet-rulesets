rule TTP_XOR_WriteProcessMemory_fd63 {
  strings:
    $key_fd63 = { aa 11 [2] 98 33 [2] 9e 06 [2] b0 06 [2] 8f 1a }

  condition:
    any of them
}