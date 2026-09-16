rule TTP_XOR_WriteProcessMemory_ba11 {
  strings:
    $key_ba11 = { ed 63 [2] df 41 [2] d9 74 [2] f7 74 [2] c8 68 }

  condition:
    any of them
}