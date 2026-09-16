rule TTP_XOR_WriteProcessMemory_8270 {
  strings:
    $key_8270 = { d5 02 [2] e7 20 [2] e1 15 [2] cf 15 [2] f0 09 }

  condition:
    any of them
}