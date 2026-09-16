rule TTP_XOR_WriteProcessMemory_8ac0 {
  strings:
    $key_8ac0 = { dd b2 [2] ef 90 [2] e9 a5 [2] c7 a5 [2] f8 b9 }

  condition:
    any of them
}