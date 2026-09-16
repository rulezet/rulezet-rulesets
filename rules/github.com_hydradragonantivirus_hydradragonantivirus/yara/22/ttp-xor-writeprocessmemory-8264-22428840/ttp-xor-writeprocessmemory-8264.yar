rule TTP_XOR_WriteProcessMemory_8264 {
  strings:
    $key_8264 = { d5 16 [2] e7 34 [2] e1 01 [2] cf 01 [2] f0 1d }

  condition:
    any of them
}