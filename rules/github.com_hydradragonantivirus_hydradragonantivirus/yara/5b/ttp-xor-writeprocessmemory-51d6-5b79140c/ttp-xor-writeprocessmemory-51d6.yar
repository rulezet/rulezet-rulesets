rule TTP_XOR_WriteProcessMemory_51d6 {
  strings:
    $key_51d6 = { 06 a4 [2] 34 86 [2] 32 b3 [2] 1c b3 [2] 23 af }

  condition:
    any of them
}