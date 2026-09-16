rule TTP_XOR_WriteProcessMemory_36c6 {
  strings:
    $key_36c6 = { 61 b4 [2] 53 96 [2] 55 a3 [2] 7b a3 [2] 44 bf }

  condition:
    any of them
}