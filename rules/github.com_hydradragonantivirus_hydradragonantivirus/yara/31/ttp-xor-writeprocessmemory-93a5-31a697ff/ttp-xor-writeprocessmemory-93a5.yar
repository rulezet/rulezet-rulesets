rule TTP_XOR_WriteProcessMemory_93a5 {
  strings:
    $key_93a5 = { c4 d7 [2] f6 f5 [2] f0 c0 [2] de c0 [2] e1 dc }

  condition:
    any of them
}