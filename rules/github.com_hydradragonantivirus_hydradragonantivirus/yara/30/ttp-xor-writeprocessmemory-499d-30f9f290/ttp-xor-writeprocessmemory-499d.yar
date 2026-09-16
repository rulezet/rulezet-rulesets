rule TTP_XOR_WriteProcessMemory_499d {
  strings:
    $key_499d = { 1e ef [2] 2c cd [2] 2a f8 [2] 04 f8 [2] 3b e4 }

  condition:
    any of them
}