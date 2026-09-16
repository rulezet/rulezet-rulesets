rule TTP_XOR_WriteProcessMemory_87f7 {
  strings:
    $key_87f7 = { d0 85 [2] e2 a7 [2] e4 92 [2] ca 92 [2] f5 8e }

  condition:
    any of them
}