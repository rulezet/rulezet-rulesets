rule TTP_XOR_WriteProcessMemory_03f3 {
  strings:
    $key_03f3 = { 54 81 [2] 66 a3 [2] 60 96 [2] 4e 96 [2] 71 8a }

  condition:
    any of them
}