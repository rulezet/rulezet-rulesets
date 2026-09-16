rule TTP_XOR_WriteProcessMemory_e666 {
  strings:
    $key_e666 = { b1 14 [2] 83 36 [2] 85 03 [2] ab 03 [2] 94 1f }

  condition:
    any of them
}