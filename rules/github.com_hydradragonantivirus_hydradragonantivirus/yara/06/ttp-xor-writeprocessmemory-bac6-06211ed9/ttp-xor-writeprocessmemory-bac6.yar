rule TTP_XOR_WriteProcessMemory_bac6 {
  strings:
    $key_bac6 = { ed b4 [2] df 96 [2] d9 a3 [2] f7 a3 [2] c8 bf }

  condition:
    any of them
}