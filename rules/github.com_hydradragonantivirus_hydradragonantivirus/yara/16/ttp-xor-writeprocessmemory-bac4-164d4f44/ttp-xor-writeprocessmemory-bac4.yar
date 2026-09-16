rule TTP_XOR_WriteProcessMemory_bac4 {
  strings:
    $key_bac4 = { ed b6 [2] df 94 [2] d9 a1 [2] f7 a1 [2] c8 bd }

  condition:
    any of them
}