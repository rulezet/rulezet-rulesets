rule TTP_XOR_WriteProcessMemory_9057 {
  strings:
    $key_9057 = { c7 25 [2] f5 07 [2] f3 32 [2] dd 32 [2] e2 2e }

  condition:
    any of them
}