rule TTP_XOR_WriteProcessMemory_bd98 {
  strings:
    $key_bd98 = { ea ea [2] d8 c8 [2] de fd [2] f0 fd [2] cf e1 }

  condition:
    any of them
}