rule TTP_XOR_WriteProcessMemory_ba35 {
  strings:
    $key_ba35 = { ed 47 [2] df 65 [2] d9 50 [2] f7 50 [2] c8 4c }

  condition:
    any of them
}