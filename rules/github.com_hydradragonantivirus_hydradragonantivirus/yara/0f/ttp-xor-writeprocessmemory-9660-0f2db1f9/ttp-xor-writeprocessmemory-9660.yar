rule TTP_XOR_WriteProcessMemory_9660 {
  strings:
    $key_9660 = { c1 12 [2] f3 30 [2] f5 05 [2] db 05 [2] e4 19 }

  condition:
    any of them
}