rule TTP_XOR_WriteProcessMemory_2ad6 {
  strings:
    $key_2ad6 = { 7d a4 [2] 4f 86 [2] 49 b3 [2] 67 b3 [2] 58 af }

  condition:
    any of them
}