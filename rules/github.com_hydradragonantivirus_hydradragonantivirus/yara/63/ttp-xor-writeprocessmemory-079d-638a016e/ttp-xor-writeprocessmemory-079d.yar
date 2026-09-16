rule TTP_XOR_WriteProcessMemory_079d {
  strings:
    $key_079d = { 50 ef [2] 62 cd [2] 64 f8 [2] 4a f8 [2] 75 e4 }

  condition:
    any of them
}