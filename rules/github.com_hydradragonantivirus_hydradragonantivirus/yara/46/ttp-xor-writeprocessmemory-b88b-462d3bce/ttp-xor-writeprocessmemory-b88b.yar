rule TTP_XOR_WriteProcessMemory_b88b {
  strings:
    $key_b88b = { ef f9 [2] dd db [2] db ee [2] f5 ee [2] ca f2 }

  condition:
    any of them
}