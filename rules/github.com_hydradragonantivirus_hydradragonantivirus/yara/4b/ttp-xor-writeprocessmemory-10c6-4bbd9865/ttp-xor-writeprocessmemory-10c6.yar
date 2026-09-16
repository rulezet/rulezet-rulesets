rule TTP_XOR_WriteProcessMemory_10c6 {
  strings:
    $key_10c6 = { 47 b4 [2] 75 96 [2] 73 a3 [2] 5d a3 [2] 62 bf }

  condition:
    any of them
}