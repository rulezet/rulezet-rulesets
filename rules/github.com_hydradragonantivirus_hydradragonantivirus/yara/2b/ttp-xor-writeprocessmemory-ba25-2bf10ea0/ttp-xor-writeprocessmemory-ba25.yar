rule TTP_XOR_WriteProcessMemory_ba25 {
  strings:
    $key_ba25 = { ed 57 [2] df 75 [2] d9 40 [2] f7 40 [2] c8 5c }

  condition:
    any of them
}