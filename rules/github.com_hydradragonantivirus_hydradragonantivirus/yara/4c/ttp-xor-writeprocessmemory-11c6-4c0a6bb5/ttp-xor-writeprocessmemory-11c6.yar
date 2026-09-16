rule TTP_XOR_WriteProcessMemory_11c6 {
  strings:
    $key_11c6 = { 46 b4 [2] 74 96 [2] 72 a3 [2] 5c a3 [2] 63 bf }

  condition:
    any of them
}