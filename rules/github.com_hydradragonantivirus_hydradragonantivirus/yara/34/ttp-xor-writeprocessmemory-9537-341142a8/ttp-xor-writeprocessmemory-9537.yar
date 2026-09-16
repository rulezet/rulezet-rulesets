rule TTP_XOR_WriteProcessMemory_9537 {
  strings:
    $key_9537 = { c2 45 [2] f0 67 [2] f6 52 [2] d8 52 [2] e7 4e }

  condition:
    any of them
}