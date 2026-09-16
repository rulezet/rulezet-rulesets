rule TTP_XOR_WriteProcessMemory_ba0c {
  strings:
    $key_ba0c = { ed 7e [2] df 5c [2] d9 69 [2] f7 69 [2] c8 75 }

  condition:
    any of them
}