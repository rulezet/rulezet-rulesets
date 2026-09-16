rule TTP_XOR_WriteProcessMemory_b49d {
  strings:
    $key_b49d = { e3 ef [2] d1 cd [2] d7 f8 [2] f9 f8 [2] c6 e4 }

  condition:
    any of them
}