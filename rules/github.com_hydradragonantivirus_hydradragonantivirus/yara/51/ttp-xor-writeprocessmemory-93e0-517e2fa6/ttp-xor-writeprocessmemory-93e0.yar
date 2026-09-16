rule TTP_XOR_WriteProcessMemory_93e0 {
  strings:
    $key_93e0 = { c4 92 [2] f6 b0 [2] f0 85 [2] de 85 [2] e1 99 }

  condition:
    any of them
}