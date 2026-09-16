rule TTP_XOR_WriteProcessMemory_bac8 {
  strings:
    $key_bac8 = { ed ba [2] df 98 [2] d9 ad [2] f7 ad [2] c8 b1 }

  condition:
    any of them
}