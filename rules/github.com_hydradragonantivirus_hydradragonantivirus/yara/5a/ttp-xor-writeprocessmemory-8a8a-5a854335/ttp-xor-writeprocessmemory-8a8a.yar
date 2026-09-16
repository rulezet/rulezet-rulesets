rule TTP_XOR_WriteProcessMemory_8a8a {
  strings:
    $key_8a8a = { dd f8 [2] ef da [2] e9 ef [2] c7 ef [2] f8 f3 }

  condition:
    any of them
}