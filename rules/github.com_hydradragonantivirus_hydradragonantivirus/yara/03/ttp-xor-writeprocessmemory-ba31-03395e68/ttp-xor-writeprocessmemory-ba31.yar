rule TTP_XOR_WriteProcessMemory_ba31 {
  strings:
    $key_ba31 = { ed 43 [2] df 61 [2] d9 54 [2] f7 54 [2] c8 48 }

  condition:
    any of them
}