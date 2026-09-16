rule TTP_XOR_WriteProcessMemory_ba66 {
  strings:
    $key_ba66 = { ed 14 [2] df 36 [2] d9 03 [2] f7 03 [2] c8 1f }

  condition:
    any of them
}