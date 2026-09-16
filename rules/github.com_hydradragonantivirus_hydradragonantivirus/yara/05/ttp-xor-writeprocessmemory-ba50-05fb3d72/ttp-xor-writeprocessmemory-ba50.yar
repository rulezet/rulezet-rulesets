rule TTP_XOR_WriteProcessMemory_ba50 {
  strings:
    $key_ba50 = { ed 22 [2] df 00 [2] d9 35 [2] f7 35 [2] c8 29 }

  condition:
    any of them
}