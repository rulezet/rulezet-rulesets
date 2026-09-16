rule TTP_XOR_WriteProcessMemory_ba3e {
  strings:
    $key_ba3e = { ed 4c [2] df 6e [2] d9 5b [2] f7 5b [2] c8 47 }

  condition:
    any of them
}