rule TTP_XOR_WriteProcessMemory_ba8b {
  strings:
    $key_ba8b = { ed f9 [2] df db [2] d9 ee [2] f7 ee [2] c8 f2 }

  condition:
    any of them
}