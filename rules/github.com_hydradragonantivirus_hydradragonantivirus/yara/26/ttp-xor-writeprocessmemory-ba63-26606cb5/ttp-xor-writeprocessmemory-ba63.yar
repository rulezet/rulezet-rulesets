rule TTP_XOR_WriteProcessMemory_ba63 {
  strings:
    $key_ba63 = { ed 11 [2] df 33 [2] d9 06 [2] f7 06 [2] c8 1a }

  condition:
    any of them
}