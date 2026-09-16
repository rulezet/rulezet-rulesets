rule TTP_XOR_WriteProcessMemory_8586 {
  strings:
    $key_8586 = { d2 f4 [2] e0 d6 [2] e6 e3 [2] c8 e3 [2] f7 ff }

  condition:
    any of them
}