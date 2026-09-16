rule TTP_XOR_WriteProcessMemory_857c {
  strings:
    $key_857c = { d2 0e [2] e0 2c [2] e6 19 [2] c8 19 [2] f7 05 }

  condition:
    any of them
}