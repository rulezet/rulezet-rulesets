rule TTP_XOR_WriteProcessMemory_90f5 {
  strings:
    $key_90f5 = { c7 87 [2] f5 a5 [2] f3 90 [2] dd 90 [2] e2 8c }

  condition:
    any of them
}