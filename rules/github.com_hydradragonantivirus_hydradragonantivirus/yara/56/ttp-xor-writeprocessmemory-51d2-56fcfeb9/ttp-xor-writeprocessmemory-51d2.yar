rule TTP_XOR_WriteProcessMemory_51d2 {
  strings:
    $key_51d2 = { 06 a0 [2] 34 82 [2] 32 b7 [2] 1c b7 [2] 23 ab }

  condition:
    any of them
}