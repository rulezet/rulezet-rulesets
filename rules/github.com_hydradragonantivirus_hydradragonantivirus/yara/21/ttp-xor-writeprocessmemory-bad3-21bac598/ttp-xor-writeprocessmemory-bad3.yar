rule TTP_XOR_WriteProcessMemory_bad3 {
  strings:
    $key_bad3 = { ed a1 [2] df 83 [2] d9 b6 [2] f7 b6 [2] c8 aa }

  condition:
    any of them
}