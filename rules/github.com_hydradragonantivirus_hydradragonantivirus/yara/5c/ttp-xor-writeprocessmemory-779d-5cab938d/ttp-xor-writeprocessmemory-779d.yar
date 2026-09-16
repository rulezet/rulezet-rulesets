rule TTP_XOR_WriteProcessMemory_779d {
  strings:
    $key_779d = { 20 ef [2] 12 cd [2] 14 f8 [2] 3a f8 [2] 05 e4 }

  condition:
    any of them
}