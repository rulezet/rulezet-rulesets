rule TTP_XOR_WriteProcessMemory_ba3b {
  strings:
    $key_ba3b = { ed 49 [2] df 6b [2] d9 5e [2] f7 5e [2] c8 42 }

  condition:
    any of them
}