rule TTP_XOR_WriteProcessMemory_ba7b {
  strings:
    $key_ba7b = { ed 09 [2] df 2b [2] d9 1e [2] f7 1e [2] c8 02 }

  condition:
    any of them
}