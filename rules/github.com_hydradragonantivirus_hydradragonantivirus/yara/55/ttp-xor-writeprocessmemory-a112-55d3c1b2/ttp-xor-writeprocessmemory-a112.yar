rule TTP_XOR_WriteProcessMemory_a112 {
  strings:
    $key_a112 = { f6 60 [2] c4 42 [2] c2 77 [2] ec 77 [2] d3 6b }

  condition:
    any of them
}