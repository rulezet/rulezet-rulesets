rule TTP_XOR_WriteProcessMemory_299d {
  strings:
    $key_299d = { 7e ef [2] 4c cd [2] 4a f8 [2] 64 f8 [2] 5b e4 }

  condition:
    any of them
}