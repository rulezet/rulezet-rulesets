rule TTP_XOR_WriteProcessMemory_ba82 {
  strings:
    $key_ba82 = { ed f0 [2] df d2 [2] d9 e7 [2] f7 e7 [2] c8 fb }

  condition:
    any of them
}