rule TTP_XOR_WriteProcessMemory_8b9d {
  strings:
    $key_8b9d = { dc ef [2] ee cd [2] e8 f8 [2] c6 f8 [2] f9 e4 }

  condition:
    any of them
}