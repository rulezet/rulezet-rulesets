rule TTP_XOR_WriteProcessMemory_54f3 {
  strings:
    $key_54f3 = { 03 81 [2] 31 a3 [2] 37 96 [2] 19 96 [2] 26 8a }

  condition:
    any of them
}