rule TTP_XOR_WriteProcessMemory_87c0 {
  strings:
    $key_87c0 = { d0 b2 [2] e2 90 [2] e4 a5 [2] ca a5 [2] f5 b9 }

  condition:
    any of them
}