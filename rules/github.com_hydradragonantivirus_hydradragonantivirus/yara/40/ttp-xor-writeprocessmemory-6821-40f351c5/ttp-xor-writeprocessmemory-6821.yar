rule TTP_XOR_WriteProcessMemory_6821 {
  strings:
    $key_6821 = { 3f 53 [2] 0d 71 [2] 0b 44 [2] 25 44 [2] 1a 58 }

  condition:
    any of them
}