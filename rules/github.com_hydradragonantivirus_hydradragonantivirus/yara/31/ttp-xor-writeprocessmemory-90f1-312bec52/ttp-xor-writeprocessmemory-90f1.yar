rule TTP_XOR_WriteProcessMemory_90f1 {
  strings:
    $key_90f1 = { c7 83 [2] f5 a1 [2] f3 94 [2] dd 94 [2] e2 88 }

  condition:
    any of them
}