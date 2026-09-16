rule TTP_XOR_WriteProcessMemory_8231 {
  strings:
    $key_8231 = { d5 43 [2] e7 61 [2] e1 54 [2] cf 54 [2] f0 48 }

  condition:
    any of them
}