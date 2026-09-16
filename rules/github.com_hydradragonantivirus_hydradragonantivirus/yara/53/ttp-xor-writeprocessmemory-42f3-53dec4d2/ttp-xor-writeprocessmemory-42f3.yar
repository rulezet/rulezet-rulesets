rule TTP_XOR_WriteProcessMemory_42f3 {
  strings:
    $key_42f3 = { 15 81 [2] 27 a3 [2] 21 96 [2] 0f 96 [2] 30 8a }

  condition:
    any of them
}