rule TTP_XOR_WriteProcessMemory_87f3 {
  strings:
    $key_87f3 = { d0 81 [2] e2 a3 [2] e4 96 [2] ca 96 [2] f5 8a }

  condition:
    any of them
}