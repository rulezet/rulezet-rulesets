rule TTP_XOR_WriteProcessMemory_ba53 {
  strings:
    $key_ba53 = { ed 21 [2] df 03 [2] d9 36 [2] f7 36 [2] c8 2a }

  condition:
    any of them
}