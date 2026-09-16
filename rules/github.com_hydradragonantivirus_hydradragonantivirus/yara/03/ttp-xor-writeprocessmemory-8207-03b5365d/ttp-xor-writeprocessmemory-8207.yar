rule TTP_XOR_WriteProcessMemory_8207 {
  strings:
    $key_8207 = { d5 75 [2] e7 57 [2] e1 62 [2] cf 62 [2] f0 7e }

  condition:
    any of them
}