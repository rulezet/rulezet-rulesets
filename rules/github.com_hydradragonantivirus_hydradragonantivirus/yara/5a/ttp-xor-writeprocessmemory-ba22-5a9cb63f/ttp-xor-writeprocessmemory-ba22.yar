rule TTP_XOR_WriteProcessMemory_ba22 {
  strings:
    $key_ba22 = { ed 50 [2] df 72 [2] d9 47 [2] f7 47 [2] c8 5b }

  condition:
    any of them
}