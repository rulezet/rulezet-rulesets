rule TTP_XOR_WriteProcessMemory_799d {
  strings:
    $key_799d = { 2e ef [2] 1c cd [2] 1a f8 [2] 34 f8 [2] 0b e4 }

  condition:
    any of them
}