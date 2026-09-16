rule TTP_XOR_WriteProcessMemory_db7b {
  strings:
    $key_db7b = { 8c 09 [2] be 2b [2] b8 1e [2] 96 1e [2] a9 02 }

  condition:
    any of them
}