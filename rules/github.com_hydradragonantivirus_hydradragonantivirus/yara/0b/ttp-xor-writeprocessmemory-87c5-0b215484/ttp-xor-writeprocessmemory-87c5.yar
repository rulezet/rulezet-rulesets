rule TTP_XOR_WriteProcessMemory_87c5 {
  strings:
    $key_87c5 = { d0 b7 [2] e2 95 [2] e4 a0 [2] ca a0 [2] f5 bc }

  condition:
    any of them
}