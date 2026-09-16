rule TTP_XOR_WriteProcessMemory_857e {
  strings:
    $key_857e = { d2 0c [2] e0 2e [2] e6 1b [2] c8 1b [2] f7 07 }

  condition:
    any of them
}