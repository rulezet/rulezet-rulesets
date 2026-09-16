rule TTP_XOR_WriteProcessMemory_ba41 {
  strings:
    $key_ba41 = { ed 33 [2] df 11 [2] d9 24 [2] f7 24 [2] c8 38 }

  condition:
    any of them
}