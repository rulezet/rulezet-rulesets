rule TTP_XOR_WriteProcessMemory_90e2 {
  strings:
    $key_90e2 = { c7 90 [2] f5 b2 [2] f3 87 [2] dd 87 [2] e2 9b }

  condition:
    any of them
}