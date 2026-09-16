rule TTP_XOR_WriteProcessMemory_9073 {
  strings:
    $key_9073 = { c7 01 [2] f5 23 [2] f3 16 [2] dd 16 [2] e2 0a }

  condition:
    any of them
}