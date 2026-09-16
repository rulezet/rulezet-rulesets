rule TTP_XOR_WriteProcessMemory_93f7 {
  strings:
    $key_93f7 = { c4 85 [2] f6 a7 [2] f0 92 [2] de 92 [2] e1 8e }

  condition:
    any of them
}