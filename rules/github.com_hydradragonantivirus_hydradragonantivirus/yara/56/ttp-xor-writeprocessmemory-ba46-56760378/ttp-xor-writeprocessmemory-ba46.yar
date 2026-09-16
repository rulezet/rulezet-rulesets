rule TTP_XOR_WriteProcessMemory_ba46 {
  strings:
    $key_ba46 = { ed 34 [2] df 16 [2] d9 23 [2] f7 23 [2] c8 3f }

  condition:
    any of them
}