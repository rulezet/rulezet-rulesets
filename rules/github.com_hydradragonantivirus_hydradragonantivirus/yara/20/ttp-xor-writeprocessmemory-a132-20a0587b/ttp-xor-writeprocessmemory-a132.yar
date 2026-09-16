rule TTP_XOR_WriteProcessMemory_a132 {
  strings:
    $key_a132 = { f6 40 [2] c4 62 [2] c2 57 [2] ec 57 [2] d3 4b }

  condition:
    any of them
}