rule TTP_XOR_WriteProcessMemory_93f5 {
  strings:
    $key_93f5 = { c4 87 [2] f6 a5 [2] f0 90 [2] de 90 [2] e1 8c }

  condition:
    any of them
}