rule TTP_XOR_WriteProcessMemory_bace {
  strings:
    $key_bace = { ed bc [2] df 9e [2] d9 ab [2] f7 ab [2] c8 b7 }

  condition:
    any of them
}