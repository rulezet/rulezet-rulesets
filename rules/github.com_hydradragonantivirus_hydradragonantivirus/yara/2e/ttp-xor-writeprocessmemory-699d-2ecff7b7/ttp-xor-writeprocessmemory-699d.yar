rule TTP_XOR_WriteProcessMemory_699d {
  strings:
    $key_699d = { 3e ef [2] 0c cd [2] 0a f8 [2] 24 f8 [2] 1b e4 }

  condition:
    any of them
}