rule TTP_XOR_WriteProcessMemory_ba57 {
  strings:
    $key_ba57 = { ed 25 [2] df 07 [2] d9 32 [2] f7 32 [2] c8 2e }

  condition:
    any of them
}