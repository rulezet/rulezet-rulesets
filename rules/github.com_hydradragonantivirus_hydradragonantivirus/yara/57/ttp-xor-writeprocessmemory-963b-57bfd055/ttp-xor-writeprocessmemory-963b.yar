rule TTP_XOR_WriteProcessMemory_963b {
  strings:
    $key_963b = { c1 49 [2] f3 6b [2] f5 5e [2] db 5e [2] e4 42 }

  condition:
    any of them
}