rule TTP_XOR_WriteProcessMemory_24c6 {
  strings:
    $key_24c6 = { 73 b4 [2] 41 96 [2] 47 a3 [2] 69 a3 [2] 56 bf }

  condition:
    any of them
}