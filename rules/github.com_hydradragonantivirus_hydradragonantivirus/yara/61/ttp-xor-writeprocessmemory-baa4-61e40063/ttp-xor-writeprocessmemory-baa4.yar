rule TTP_XOR_WriteProcessMemory_baa4 {
  strings:
    $key_baa4 = { ed d6 [2] df f4 [2] d9 c1 [2] f7 c1 [2] c8 dd }

  condition:
    any of them
}