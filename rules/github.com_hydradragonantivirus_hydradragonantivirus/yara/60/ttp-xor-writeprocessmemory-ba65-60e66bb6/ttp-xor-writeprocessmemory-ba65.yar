rule TTP_XOR_WriteProcessMemory_ba65 {
  strings:
    $key_ba65 = { ed 17 [2] df 35 [2] d9 00 [2] f7 00 [2] c8 1c }

  condition:
    any of them
}