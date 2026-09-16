rule TTP_XOR_WriteProcessMemory_ba29 {
  strings:
    $key_ba29 = { ed 5b [2] df 79 [2] d9 4c [2] f7 4c [2] c8 50 }

  condition:
    any of them
}