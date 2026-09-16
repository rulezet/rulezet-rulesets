rule TTP_XOR_WriteProcessMemory_2fd6 {
  strings:
    $key_2fd6 = { 78 a4 [2] 4a 86 [2] 4c b3 [2] 62 b3 [2] 5d af }

  condition:
    any of them
}