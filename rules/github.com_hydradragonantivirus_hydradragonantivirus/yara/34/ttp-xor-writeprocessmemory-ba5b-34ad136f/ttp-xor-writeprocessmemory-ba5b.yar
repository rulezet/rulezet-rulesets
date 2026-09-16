rule TTP_XOR_WriteProcessMemory_ba5b {
  strings:
    $key_ba5b = { ed 29 [2] df 0b [2] d9 3e [2] f7 3e [2] c8 22 }

  condition:
    any of them
}