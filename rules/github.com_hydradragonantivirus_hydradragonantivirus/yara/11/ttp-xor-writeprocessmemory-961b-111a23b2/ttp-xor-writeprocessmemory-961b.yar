rule TTP_XOR_WriteProcessMemory_961b {
  strings:
    $key_961b = { c1 69 [2] f3 4b [2] f5 7e [2] db 7e [2] e4 62 }

  condition:
    any of them
}