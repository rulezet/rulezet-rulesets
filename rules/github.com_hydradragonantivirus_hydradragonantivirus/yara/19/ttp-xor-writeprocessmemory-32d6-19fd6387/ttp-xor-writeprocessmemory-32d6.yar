rule TTP_XOR_WriteProcessMemory_32d6 {
  strings:
    $key_32d6 = { 65 a4 [2] 57 86 [2] 51 b3 [2] 7f b3 [2] 40 af }

  condition:
    any of them
}