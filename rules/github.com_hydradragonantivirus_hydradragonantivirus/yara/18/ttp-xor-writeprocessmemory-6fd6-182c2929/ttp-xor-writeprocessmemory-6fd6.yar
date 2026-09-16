rule TTP_XOR_WriteProcessMemory_6fd6 {
  strings:
    $key_6fd6 = { 38 a4 [2] 0a 86 [2] 0c b3 [2] 22 b3 [2] 1d af }

  condition:
    any of them
}