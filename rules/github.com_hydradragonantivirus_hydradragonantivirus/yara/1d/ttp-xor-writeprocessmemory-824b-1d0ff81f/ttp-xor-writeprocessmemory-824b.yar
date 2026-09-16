rule TTP_XOR_WriteProcessMemory_824b {
  strings:
    $key_824b = { d5 39 [2] e7 1b [2] e1 2e [2] cf 2e [2] f0 32 }

  condition:
    any of them
}