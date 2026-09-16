rule TTP_XOR_WriteProcessMemory_87e0 {
  strings:
    $key_87e0 = { d0 92 [2] e2 b0 [2] e4 85 [2] ca 85 [2] f5 99 }

  condition:
    any of them
}