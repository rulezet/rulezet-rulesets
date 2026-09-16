rule TTP_XOR_WriteProcessMemory_34c6 {
  strings:
    $key_34c6 = { 63 b4 [2] 51 96 [2] 57 a3 [2] 79 a3 [2] 46 bf }

  condition:
    any of them
}