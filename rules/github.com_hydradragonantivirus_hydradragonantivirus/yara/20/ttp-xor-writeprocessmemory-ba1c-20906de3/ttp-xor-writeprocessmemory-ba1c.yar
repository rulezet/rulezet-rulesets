rule TTP_XOR_WriteProcessMemory_ba1c {
  strings:
    $key_ba1c = { ed 6e [2] df 4c [2] d9 79 [2] f7 79 [2] c8 65 }

  condition:
    any of them
}