rule TTP_XOR_WriteProcessMemory_8298 {
  strings:
    $key_8298 = { d5 ea [2] e7 c8 [2] e1 fd [2] cf fd [2] f0 e1 }

  condition:
    any of them
}