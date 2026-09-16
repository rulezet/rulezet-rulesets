rule TTP_XOR_WriteProcessMemory_ba62 {
  strings:
    $key_ba62 = { ed 10 [2] df 32 [2] d9 07 [2] f7 07 [2] c8 1b }

  condition:
    any of them
}