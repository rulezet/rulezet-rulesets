rule TTP_XOR_WriteProcessMemory_20c6 {
  strings:
    $key_20c6 = { 77 b4 [2] 45 96 [2] 43 a3 [2] 6d a3 [2] 52 bf }

  condition:
    any of them
}