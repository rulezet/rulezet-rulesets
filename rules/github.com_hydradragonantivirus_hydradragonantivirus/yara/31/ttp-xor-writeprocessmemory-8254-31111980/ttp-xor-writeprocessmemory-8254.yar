rule TTP_XOR_WriteProcessMemory_8254 {
  strings:
    $key_8254 = { d5 26 [2] e7 04 [2] e1 31 [2] cf 31 [2] f0 2d }

  condition:
    any of them
}