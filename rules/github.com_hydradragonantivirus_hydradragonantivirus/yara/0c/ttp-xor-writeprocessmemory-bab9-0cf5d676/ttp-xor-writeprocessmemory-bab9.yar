rule TTP_XOR_WriteProcessMemory_bab9 {
  strings:
    $key_bab9 = { ed cb [2] df e9 [2] d9 dc [2] f7 dc [2] c8 c0 }

  condition:
    any of them
}