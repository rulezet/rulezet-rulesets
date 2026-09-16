rule TTP_XOR_WriteProcessMemory_8249 {
  strings:
    $key_8249 = { d5 3b [2] e7 19 [2] e1 2c [2] cf 2c [2] f0 30 }

  condition:
    any of them
}