rule TTP_XOR_WriteProcessMemory_23c6 {
  strings:
    $key_23c6 = { 74 b4 [2] 46 96 [2] 40 a3 [2] 6e a3 [2] 51 bf }

  condition:
    any of them
}