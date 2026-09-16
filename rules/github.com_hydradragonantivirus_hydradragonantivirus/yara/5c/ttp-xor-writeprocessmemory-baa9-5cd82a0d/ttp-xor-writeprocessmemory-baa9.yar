rule TTP_XOR_WriteProcessMemory_baa9 {
  strings:
    $key_baa9 = { ed db [2] df f9 [2] d9 cc [2] f7 cc [2] c8 d0 }

  condition:
    any of them
}