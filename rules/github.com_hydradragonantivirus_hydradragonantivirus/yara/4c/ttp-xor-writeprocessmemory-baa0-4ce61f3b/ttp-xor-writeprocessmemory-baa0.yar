rule TTP_XOR_WriteProcessMemory_baa0 {
  strings:
    $key_baa0 = { ed d2 [2] df f0 [2] d9 c5 [2] f7 c5 [2] c8 d9 }

  condition:
    any of them
}