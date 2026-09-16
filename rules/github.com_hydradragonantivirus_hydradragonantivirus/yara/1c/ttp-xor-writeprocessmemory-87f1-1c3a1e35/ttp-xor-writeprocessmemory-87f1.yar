rule TTP_XOR_WriteProcessMemory_87f1 {
  strings:
    $key_87f1 = { d0 83 [2] e2 a1 [2] e4 94 [2] ca 94 [2] f5 88 }

  condition:
    any of them
}