rule TTP_XOR_WriteProcessMemory_bab2 {
  strings:
    $key_bab2 = { ed c0 [2] df e2 [2] d9 d7 [2] f7 d7 [2] c8 cb }

  condition:
    any of them
}