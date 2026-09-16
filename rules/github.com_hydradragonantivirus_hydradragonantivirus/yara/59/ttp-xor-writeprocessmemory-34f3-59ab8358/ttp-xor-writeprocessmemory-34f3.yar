rule TTP_XOR_WriteProcessMemory_34f3 {
  strings:
    $key_34f3 = { 63 81 [2] 51 a3 [2] 57 96 [2] 79 96 [2] 46 8a }

  condition:
    any of them
}