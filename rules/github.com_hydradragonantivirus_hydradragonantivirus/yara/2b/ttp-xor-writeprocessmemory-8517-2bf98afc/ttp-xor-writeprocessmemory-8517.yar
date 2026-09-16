rule TTP_XOR_WriteProcessMemory_8517 {
  strings:
    $key_8517 = { d2 65 [2] e0 47 [2] e6 72 [2] c8 72 [2] f7 6e }

  condition:
    any of them
}