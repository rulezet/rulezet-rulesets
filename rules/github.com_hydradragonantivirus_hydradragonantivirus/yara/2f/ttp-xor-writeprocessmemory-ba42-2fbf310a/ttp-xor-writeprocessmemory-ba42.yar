rule TTP_XOR_WriteProcessMemory_ba42 {
  strings:
    $key_ba42 = { ed 30 [2] df 12 [2] d9 27 [2] f7 27 [2] c8 3b }

  condition:
    any of them
}