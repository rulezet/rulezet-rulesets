rule TTP_XOR_WriteProcessMemory_90c6 {
  strings:
    $key_90c6 = { c7 b4 [2] f5 96 [2] f3 a3 [2] dd a3 [2] e2 bf }

  condition:
    any of them
}