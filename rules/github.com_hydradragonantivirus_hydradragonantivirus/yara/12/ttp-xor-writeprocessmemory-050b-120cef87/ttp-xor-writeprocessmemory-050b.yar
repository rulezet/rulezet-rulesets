rule TTP_XOR_WriteProcessMemory_050b {
  strings:
    $key_050b = { 52 79 [2] 60 5b [2] 66 6e [2] 48 6e [2] 77 72 }

  condition:
    any of them
}