rule TTP_XOR_WriteProcessMemory_6802 {
  strings:
    $key_6802 = { 3f 70 [2] 0d 52 [2] 0b 67 [2] 25 67 [2] 1a 7b }

  condition:
    any of them
}