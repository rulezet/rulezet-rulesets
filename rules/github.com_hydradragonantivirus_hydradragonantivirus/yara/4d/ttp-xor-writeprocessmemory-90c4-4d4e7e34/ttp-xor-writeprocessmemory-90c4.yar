rule TTP_XOR_WriteProcessMemory_90c4 {
  strings:
    $key_90c4 = { c7 b6 [2] f5 94 [2] f3 a1 [2] dd a1 [2] e2 bd }

  condition:
    any of them
}