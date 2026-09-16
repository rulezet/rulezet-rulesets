rule TTP_XOR_WriteProcessMemory_9644 {
  strings:
    $key_9644 = { c1 36 [2] f3 14 [2] f5 21 [2] db 21 [2] e4 3d }

  condition:
    any of them
}