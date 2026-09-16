rule TTP_XOR_WriteProcessMemory_051b {
  strings:
    $key_051b = { 52 69 [2] 60 4b [2] 66 7e [2] 48 7e [2] 77 62 }

  condition:
    any of them
}