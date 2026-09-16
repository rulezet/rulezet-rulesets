rule TTP_XOR_WriteProcessMemory_11d2 {
  strings:
    $key_11d2 = { 46 a0 [2] 74 82 [2] 72 b7 [2] 5c b7 [2] 63 ab }

  condition:
    any of them
}