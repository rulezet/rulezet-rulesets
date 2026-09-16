rule TTP_XOR_WriteProcessMemory_32c6 {
  strings:
    $key_32c6 = { 65 b4 [2] 57 96 [2] 51 a3 [2] 7f a3 [2] 40 bf }

  condition:
    any of them
}