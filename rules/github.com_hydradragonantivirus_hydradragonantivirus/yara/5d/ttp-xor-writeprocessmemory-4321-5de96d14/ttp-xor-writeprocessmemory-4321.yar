rule TTP_XOR_WriteProcessMemory_4321 {
  strings:
    $key_4321 = { 14 53 [2] 26 71 [2] 20 44 [2] 0e 44 [2] 31 58 }

  condition:
    any of them
}