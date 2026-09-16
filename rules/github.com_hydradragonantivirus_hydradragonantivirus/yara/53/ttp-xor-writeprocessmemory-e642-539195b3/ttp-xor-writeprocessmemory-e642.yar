rule TTP_XOR_WriteProcessMemory_e642 {
  strings:
    $key_e642 = { b1 30 [2] 83 12 [2] 85 27 [2] ab 27 [2] 94 3b }

  condition:
    any of them
}