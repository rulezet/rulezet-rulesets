rule TTP_XOR_WriteProcessMemory_579d {
  strings:
    $key_579d = { 00 ef [2] 32 cd [2] 34 f8 [2] 1a f8 [2] 25 e4 }

  condition:
    any of them
}