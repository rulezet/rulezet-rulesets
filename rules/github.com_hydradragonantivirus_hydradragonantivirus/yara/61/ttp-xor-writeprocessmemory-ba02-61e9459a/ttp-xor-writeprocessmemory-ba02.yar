rule TTP_XOR_WriteProcessMemory_ba02 {
  strings:
    $key_ba02 = { ed 70 [2] df 52 [2] d9 67 [2] f7 67 [2] c8 7b }

  condition:
    any of them
}