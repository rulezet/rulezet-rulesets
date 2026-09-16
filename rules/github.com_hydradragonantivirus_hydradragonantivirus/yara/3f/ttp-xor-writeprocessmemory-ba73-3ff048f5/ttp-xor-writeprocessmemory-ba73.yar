rule TTP_XOR_WriteProcessMemory_ba73 {
  strings:
    $key_ba73 = { ed 01 [2] df 23 [2] d9 16 [2] f7 16 [2] c8 0a }

  condition:
    any of them
}