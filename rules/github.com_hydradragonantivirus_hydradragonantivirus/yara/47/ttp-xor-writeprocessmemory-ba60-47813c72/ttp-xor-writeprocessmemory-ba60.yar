rule TTP_XOR_WriteProcessMemory_ba60 {
  strings:
    $key_ba60 = { ed 12 [2] df 30 [2] d9 05 [2] f7 05 [2] c8 19 }

  condition:
    any of them
}