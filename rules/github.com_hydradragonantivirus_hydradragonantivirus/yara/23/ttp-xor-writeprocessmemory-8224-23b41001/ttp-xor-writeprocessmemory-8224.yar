rule TTP_XOR_WriteProcessMemory_8224 {
  strings:
    $key_8224 = { d5 56 [2] e7 74 [2] e1 41 [2] cf 41 [2] f0 5d }

  condition:
    any of them
}