rule TTP_XOR_WriteProcessMemory_3730 {
  strings:
    $key_3730 = { 60 42 [2] 52 60 [2] 54 55 [2] 7a 55 [2] 45 49 }

  condition:
    any of them
}