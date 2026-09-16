rule TTP_XOR_WriteProcessMemory_a151 {
  strings:
    $key_a151 = { f6 23 [2] c4 01 [2] c2 34 [2] ec 34 [2] d3 28 }

  condition:
    any of them
}