rule TTP_XOR_WriteProcessMemory_03d6 {
  strings:
    $key_03d6 = { 54 a4 [2] 66 86 [2] 60 b3 [2] 4e b3 [2] 71 af }

  condition:
    any of them
}