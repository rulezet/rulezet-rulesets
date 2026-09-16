rule TTP_XOR_WriteProcessMemory_e708 {
  strings:
    $key_e708 = { b0 7a [2] 82 58 [2] 84 6d [2] aa 6d [2] 95 71 }

  condition:
    any of them
}