rule TTP_XOR_WriteProcessMemory_93a4 {
  strings:
    $key_93a4 = { c4 d6 [2] f6 f4 [2] f0 c1 [2] de c1 [2] e1 dd }

  condition:
    any of them
}