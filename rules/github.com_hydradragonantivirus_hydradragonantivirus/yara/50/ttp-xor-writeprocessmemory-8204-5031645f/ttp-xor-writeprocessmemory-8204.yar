rule TTP_XOR_WriteProcessMemory_8204 {
  strings:
    $key_8204 = { d5 76 [2] e7 54 [2] e1 61 [2] cf 61 [2] f0 7d }

  condition:
    any of them
}