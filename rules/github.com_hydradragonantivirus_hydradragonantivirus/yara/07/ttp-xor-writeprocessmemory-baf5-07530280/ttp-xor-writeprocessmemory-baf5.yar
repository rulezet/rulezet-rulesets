rule TTP_XOR_WriteProcessMemory_baf5 {
  strings:
    $key_baf5 = { ed 87 [2] df a5 [2] d9 90 [2] f7 90 [2] c8 8c }

  condition:
    any of them
}