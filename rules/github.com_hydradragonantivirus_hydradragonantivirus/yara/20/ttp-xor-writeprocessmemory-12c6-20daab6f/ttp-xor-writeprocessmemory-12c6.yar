rule TTP_XOR_WriteProcessMemory_12c6 {
  strings:
    $key_12c6 = { 45 b4 [2] 77 96 [2] 71 a3 [2] 5f a3 [2] 60 bf }

  condition:
    any of them
}