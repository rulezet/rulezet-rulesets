rule TTP_XOR_WriteProcessMemory_7fd6 {
  strings:
    $key_7fd6 = { 28 a4 [2] 1a 86 [2] 1c b3 [2] 32 b3 [2] 0d af }

  condition:
    any of them
}