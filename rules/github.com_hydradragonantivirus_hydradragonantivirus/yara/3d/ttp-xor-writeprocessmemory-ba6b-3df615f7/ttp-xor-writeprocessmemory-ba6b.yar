rule TTP_XOR_WriteProcessMemory_ba6b {
  strings:
    $key_ba6b = { ed 19 [2] df 3b [2] d9 0e [2] f7 0e [2] c8 12 }

  condition:
    any of them
}