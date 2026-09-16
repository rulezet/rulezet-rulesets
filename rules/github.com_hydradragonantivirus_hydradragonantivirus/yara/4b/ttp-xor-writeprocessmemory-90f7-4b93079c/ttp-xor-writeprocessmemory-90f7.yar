rule TTP_XOR_WriteProcessMemory_90f7 {
  strings:
    $key_90f7 = { c7 85 [2] f5 a7 [2] f3 92 [2] dd 92 [2] e2 8e }

  condition:
    any of them
}