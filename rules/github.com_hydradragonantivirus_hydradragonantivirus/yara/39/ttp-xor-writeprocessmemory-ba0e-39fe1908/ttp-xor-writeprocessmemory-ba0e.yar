rule TTP_XOR_WriteProcessMemory_ba0e {
  strings:
    $key_ba0e = { ed 7c [2] df 5e [2] d9 6b [2] f7 6b [2] c8 77 }

  condition:
    any of them
}