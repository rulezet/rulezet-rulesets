rule TTP_XOR_WriteProcessMemory_9064 {
  strings:
    $key_9064 = { c7 16 [2] f5 34 [2] f3 01 [2] dd 01 [2] e2 1d }

  condition:
    any of them
}