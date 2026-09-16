rule TTP_XOR_WriteProcessMemory_ba47 {
  strings:
    $key_ba47 = { ed 35 [2] df 17 [2] d9 22 [2] f7 22 [2] c8 3e }

  condition:
    any of them
}