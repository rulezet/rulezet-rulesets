rule TTP_XOR_WriteProcessMemory_ba6e {
  strings:
    $key_ba6e = { ed 1c [2] df 3e [2] d9 0b [2] f7 0b [2] c8 17 }

  condition:
    any of them
}