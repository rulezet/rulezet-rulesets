rule TTP_XOR_WriteProcessMemory_ba7d {
  strings:
    $key_ba7d = { ed 0f [2] df 2d [2] d9 18 [2] f7 18 [2] c8 04 }

  condition:
    any of them
}