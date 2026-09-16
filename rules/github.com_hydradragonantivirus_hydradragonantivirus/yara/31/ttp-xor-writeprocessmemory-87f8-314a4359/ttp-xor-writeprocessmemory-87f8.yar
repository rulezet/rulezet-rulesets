rule TTP_XOR_WriteProcessMemory_87f8 {
  strings:
    $key_87f8 = { d0 8a [2] e2 a8 [2] e4 9d [2] ca 9d [2] f5 81 }

  condition:
    any of them
}