rule TTP_XOR_WriteProcessMemory_9670 {
  strings:
    $key_9670 = { c1 02 [2] f3 20 [2] f5 15 [2] db 15 [2] e4 09 }

  condition:
    any of them
}