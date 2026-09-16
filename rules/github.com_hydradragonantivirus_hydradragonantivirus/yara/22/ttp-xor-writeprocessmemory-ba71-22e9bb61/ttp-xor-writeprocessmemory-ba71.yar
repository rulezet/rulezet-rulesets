rule TTP_XOR_WriteProcessMemory_ba71 {
  strings:
    $key_ba71 = { ed 03 [2] df 21 [2] d9 14 [2] f7 14 [2] c8 08 }

  condition:
    any of them
}