rule TTP_XOR_WriteProcessMemory_ba4e {
  strings:
    $key_ba4e = { ed 3c [2] df 1e [2] d9 2b [2] f7 2b [2] c8 37 }

  condition:
    any of them
}