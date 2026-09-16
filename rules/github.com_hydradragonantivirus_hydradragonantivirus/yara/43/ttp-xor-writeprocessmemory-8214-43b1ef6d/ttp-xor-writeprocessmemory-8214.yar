rule TTP_XOR_WriteProcessMemory_8214 {
  strings:
    $key_8214 = { d5 66 [2] e7 44 [2] e1 71 [2] cf 71 [2] f0 6d }

  condition:
    any of them
}