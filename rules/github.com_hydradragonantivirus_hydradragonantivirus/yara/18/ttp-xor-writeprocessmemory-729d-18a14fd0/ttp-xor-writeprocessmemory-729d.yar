rule TTP_XOR_WriteProcessMemory_729d {
  strings:
    $key_729d = { 25 ef [2] 17 cd [2] 11 f8 [2] 3f f8 [2] 00 e4 }

  condition:
    any of them
}