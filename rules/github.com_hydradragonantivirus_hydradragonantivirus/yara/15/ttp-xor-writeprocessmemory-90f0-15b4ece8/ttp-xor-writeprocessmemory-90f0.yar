rule TTP_XOR_WriteProcessMemory_90f0 {
  strings:
    $key_90f0 = { c7 82 [2] f5 a0 [2] f3 95 [2] dd 95 [2] e2 89 }

  condition:
    any of them
}