rule TTP_XOR_WriteProcessMemory_ba2e {
  strings:
    $key_ba2e = { ed 5c [2] df 7e [2] d9 4b [2] f7 4b [2] c8 57 }

  condition:
    any of them
}