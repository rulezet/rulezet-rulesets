rule TTP_XOR_WriteProcessMemory_baf4 {
  strings:
    $key_baf4 = { ed 86 [2] df a4 [2] d9 91 [2] f7 91 [2] c8 8d }

  condition:
    any of them
}