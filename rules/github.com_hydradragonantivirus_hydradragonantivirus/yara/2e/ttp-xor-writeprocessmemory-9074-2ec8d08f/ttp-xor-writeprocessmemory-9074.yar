rule TTP_XOR_WriteProcessMemory_9074 {
  strings:
    $key_9074 = { c7 06 [2] f5 24 [2] f3 11 [2] dd 11 [2] e2 0d }

  condition:
    any of them
}