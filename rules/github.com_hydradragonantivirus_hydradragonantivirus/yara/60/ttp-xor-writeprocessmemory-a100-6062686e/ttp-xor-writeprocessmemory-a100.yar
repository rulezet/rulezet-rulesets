rule TTP_XOR_WriteProcessMemory_a100 {
  strings:
    $key_a100 = { f6 72 [2] c4 50 [2] c2 65 [2] ec 65 [2] d3 79 }

  condition:
    any of them
}