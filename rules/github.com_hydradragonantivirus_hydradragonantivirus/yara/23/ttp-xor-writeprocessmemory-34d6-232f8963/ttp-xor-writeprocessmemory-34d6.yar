rule TTP_XOR_WriteProcessMemory_34d6 {
  strings:
    $key_34d6 = { 63 a4 [2] 51 86 [2] 57 b3 [2] 79 b3 [2] 46 af }

  condition:
    any of them
}