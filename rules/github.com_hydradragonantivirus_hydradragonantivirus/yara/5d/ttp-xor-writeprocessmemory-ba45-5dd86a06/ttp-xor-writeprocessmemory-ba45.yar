rule TTP_XOR_WriteProcessMemory_ba45 {
  strings:
    $key_ba45 = { ed 37 [2] df 15 [2] d9 20 [2] f7 20 [2] c8 3c }

  condition:
    any of them
}