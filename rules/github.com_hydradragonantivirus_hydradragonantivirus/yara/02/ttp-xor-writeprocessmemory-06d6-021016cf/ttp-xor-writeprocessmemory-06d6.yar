rule TTP_XOR_WriteProcessMemory_06d6 {
  strings:
    $key_06d6 = { 51 a4 [2] 63 86 [2] 65 b3 [2] 4b b3 [2] 74 af }

  condition:
    any of them
}