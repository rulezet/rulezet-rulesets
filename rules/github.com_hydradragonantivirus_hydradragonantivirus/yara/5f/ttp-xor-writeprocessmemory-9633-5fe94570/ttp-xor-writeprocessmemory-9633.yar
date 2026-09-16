rule TTP_XOR_WriteProcessMemory_9633 {
  strings:
    $key_9633 = { c1 41 [2] f3 63 [2] f5 56 [2] db 56 [2] e4 4a }

  condition:
    any of them
}