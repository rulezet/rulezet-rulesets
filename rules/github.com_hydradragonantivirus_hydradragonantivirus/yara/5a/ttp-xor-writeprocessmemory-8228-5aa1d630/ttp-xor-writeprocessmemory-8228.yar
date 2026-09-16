rule TTP_XOR_WriteProcessMemory_8228 {
  strings:
    $key_8228 = { d5 5a [2] e7 78 [2] e1 4d [2] cf 4d [2] f0 51 }

  condition:
    any of them
}