rule TTP_XOR_WriteProcessMemory_9627 {
  strings:
    $key_9627 = { c1 55 [2] f3 77 [2] f5 42 [2] db 42 [2] e4 5e }

  condition:
    any of them
}