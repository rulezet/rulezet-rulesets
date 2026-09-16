rule TTP_XOR_WriteProcessMemory_a142 {
  strings:
    $key_a142 = { f6 30 [2] c4 12 [2] c2 27 [2] ec 27 [2] d3 3b }

  condition:
    any of them
}