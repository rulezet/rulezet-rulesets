rule TTP_XOR_WriteProcessMemory_a1f1 {
  strings:
    $key_a1f1 = { f6 83 [2] c4 a1 [2] c2 94 [2] ec 94 [2] d3 88 }

  condition:
    any of them
}