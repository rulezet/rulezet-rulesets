rule TTP_XOR_WriteProcessMemory_8203 {
  strings:
    $key_8203 = { d5 71 [2] e7 53 [2] e1 66 [2] cf 66 [2] f0 7a }

  condition:
    any of them
}