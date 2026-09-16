rule TTP_XOR_WriteProcessMemory_ba94 {
  strings:
    $key_ba94 = { ed e6 [2] df c4 [2] d9 f1 [2] f7 f1 [2] c8 ed }

  condition:
    any of them
}