rule TTP_XOR_WriteProcessMemory_70d6 {
  strings:
    $key_70d6 = { 27 a4 [2] 15 86 [2] 13 b3 [2] 3d b3 [2] 02 af }

  condition:
    any of them
}