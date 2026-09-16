rule TTP_XOR_WriteProcessMemory_40c6 {
  strings:
    $key_40c6 = { 17 b4 [2] 25 96 [2] 23 a3 [2] 0d a3 [2] 32 bf }

  condition:
    any of them
}