rule TTP_XOR_WriteProcessMemory_829d {
  strings:
    $key_829d = { d5 ef [2] e7 cd [2] e1 f8 [2] cf f8 [2] f0 e4 }

  condition:
    any of them
}