rule TTP_XOR_WriteProcessMemory_bad6 {
  strings:
    $key_bad6 = { ed a4 [2] df 86 [2] d9 b3 [2] f7 b3 [2] c8 af }

  condition:
    any of them
}