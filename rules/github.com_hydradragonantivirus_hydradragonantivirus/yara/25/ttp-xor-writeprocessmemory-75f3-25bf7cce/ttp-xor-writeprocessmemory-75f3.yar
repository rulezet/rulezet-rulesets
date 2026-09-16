rule TTP_XOR_WriteProcessMemory_75f3 {
  strings:
    $key_75f3 = { 22 81 [2] 10 a3 [2] 16 96 [2] 38 96 [2] 07 8a }

  condition:
    any of them
}