rule TTP_XOR_WriteProcessMemory_8545 {
  strings:
    $key_8545 = { d2 37 [2] e0 15 [2] e6 20 [2] c8 20 [2] f7 3c }

  condition:
    any of them
}