rule TTP_XOR_WriteProcessMemory_21c6 {
  strings:
    $key_21c6 = { 76 b4 [2] 44 96 [2] 42 a3 [2] 6c a3 [2] 53 bf }

  condition:
    any of them
}