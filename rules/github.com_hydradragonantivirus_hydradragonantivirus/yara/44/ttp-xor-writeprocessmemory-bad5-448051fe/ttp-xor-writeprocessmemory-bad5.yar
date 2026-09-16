rule TTP_XOR_WriteProcessMemory_bad5 {
  strings:
    $key_bad5 = { ed a7 [2] df 85 [2] d9 b0 [2] f7 b0 [2] c8 ac }

  condition:
    any of them
}