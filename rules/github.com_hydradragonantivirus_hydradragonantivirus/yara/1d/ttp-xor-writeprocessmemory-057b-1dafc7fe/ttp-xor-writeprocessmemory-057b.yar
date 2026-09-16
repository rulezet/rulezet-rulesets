rule TTP_XOR_WriteProcessMemory_057b {
  strings:
    $key_057b = { 52 09 [2] 60 2b [2] 66 1e [2] 48 1e [2] 77 02 }

  condition:
    any of them
}