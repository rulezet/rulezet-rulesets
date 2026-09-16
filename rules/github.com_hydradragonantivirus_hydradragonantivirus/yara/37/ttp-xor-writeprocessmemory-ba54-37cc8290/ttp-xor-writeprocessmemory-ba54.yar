rule TTP_XOR_WriteProcessMemory_ba54 {
  strings:
    $key_ba54 = { ed 26 [2] df 04 [2] d9 31 [2] f7 31 [2] c8 2d }

  condition:
    any of them
}