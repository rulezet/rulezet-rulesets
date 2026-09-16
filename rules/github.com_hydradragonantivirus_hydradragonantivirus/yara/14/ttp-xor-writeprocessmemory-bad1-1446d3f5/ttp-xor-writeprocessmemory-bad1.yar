rule TTP_XOR_WriteProcessMemory_bad1 {
  strings:
    $key_bad1 = { ed a3 [2] df 81 [2] d9 b4 [2] f7 b4 [2] c8 a8 }

  condition:
    any of them
}