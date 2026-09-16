rule TTP_XOR_WriteProcessMemory_ba2d {
  strings:
    $key_ba2d = { ed 5f [2] df 7d [2] d9 48 [2] f7 48 [2] c8 54 }

  condition:
    any of them
}