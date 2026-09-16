rule TTP_XOR_WriteProcessMemory_9601 {
  strings:
    $key_9601 = { c1 73 [2] f3 51 [2] f5 64 [2] db 64 [2] e4 78 }

  condition:
    any of them
}