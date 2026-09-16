rule TTP_XOR_WriteProcessMemory_93d5 {
  strings:
    $key_93d5 = { c4 a7 [2] f6 85 [2] f0 b0 [2] de b0 [2] e1 ac }

  condition:
    any of them
}