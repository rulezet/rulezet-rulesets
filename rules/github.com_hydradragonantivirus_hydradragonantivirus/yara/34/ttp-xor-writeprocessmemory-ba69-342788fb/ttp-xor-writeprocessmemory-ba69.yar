rule TTP_XOR_WriteProcessMemory_ba69 {
  strings:
    $key_ba69 = { ed 1b [2] df 39 [2] d9 0c [2] f7 0c [2] c8 10 }

  condition:
    any of them
}