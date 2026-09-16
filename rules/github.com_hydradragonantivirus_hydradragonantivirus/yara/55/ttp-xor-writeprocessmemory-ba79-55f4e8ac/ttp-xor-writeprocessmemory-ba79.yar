rule TTP_XOR_WriteProcessMemory_ba79 {
  strings:
    $key_ba79 = { ed 0b [2] df 29 [2] d9 1c [2] f7 1c [2] c8 00 }

  condition:
    any of them
}