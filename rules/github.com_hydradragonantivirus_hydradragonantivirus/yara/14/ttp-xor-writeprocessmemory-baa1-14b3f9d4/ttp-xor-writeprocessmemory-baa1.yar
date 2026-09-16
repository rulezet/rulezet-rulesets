rule TTP_XOR_WriteProcessMemory_baa1 {
  strings:
    $key_baa1 = { ed d3 [2] df f1 [2] d9 c4 [2] f7 c4 [2] c8 d8 }

  condition:
    any of them
}