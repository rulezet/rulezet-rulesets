rule TTP_XOR_WriteProcessMemory_9634 {
  strings:
    $key_9634 = { c1 46 [2] f3 64 [2] f5 51 [2] db 51 [2] e4 4d }

  condition:
    any of them
}