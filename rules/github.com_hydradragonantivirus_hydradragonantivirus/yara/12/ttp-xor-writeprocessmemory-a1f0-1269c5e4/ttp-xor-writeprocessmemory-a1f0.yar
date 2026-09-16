rule TTP_XOR_WriteProcessMemory_a1f0 {
  strings:
    $key_a1f0 = { f6 82 [2] c4 a0 [2] c2 95 [2] ec 95 [2] d3 89 }

  condition:
    any of them
}