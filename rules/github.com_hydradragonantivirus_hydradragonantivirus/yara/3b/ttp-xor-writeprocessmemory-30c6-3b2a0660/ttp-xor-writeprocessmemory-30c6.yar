rule TTP_XOR_WriteProcessMemory_30c6 {
  strings:
    $key_30c6 = { 67 b4 [2] 55 96 [2] 53 a3 [2] 7d a3 [2] 42 bf }

  condition:
    any of them
}