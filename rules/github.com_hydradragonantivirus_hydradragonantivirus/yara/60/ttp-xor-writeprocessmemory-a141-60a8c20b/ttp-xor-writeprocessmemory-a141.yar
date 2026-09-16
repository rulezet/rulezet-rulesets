rule TTP_XOR_WriteProcessMemory_a141 {
  strings:
    $key_a141 = { f6 33 [2] c4 11 [2] c2 24 [2] ec 24 [2] d3 38 }

  condition:
    any of them
}