rule TTP_XOR_WriteProcessMemory_ba17 {
  strings:
    $key_ba17 = { ed 65 [2] df 47 [2] d9 72 [2] f7 72 [2] c8 6e }

  condition:
    any of them
}