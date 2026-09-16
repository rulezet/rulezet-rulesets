rule TTP_XOR_WriteProcessMemory_71d6 {
  strings:
    $key_71d6 = { 26 a4 [2] 14 86 [2] 12 b3 [2] 3c b3 [2] 03 af }

  condition:
    any of them
}