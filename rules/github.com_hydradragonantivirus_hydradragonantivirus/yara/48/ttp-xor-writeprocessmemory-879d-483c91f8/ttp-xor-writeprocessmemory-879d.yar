rule TTP_XOR_WriteProcessMemory_879d {
  strings:
    $key_879d = { d0 ef [2] e2 cd [2] e4 f8 [2] ca f8 [2] f5 e4 }

  condition:
    any of them
}