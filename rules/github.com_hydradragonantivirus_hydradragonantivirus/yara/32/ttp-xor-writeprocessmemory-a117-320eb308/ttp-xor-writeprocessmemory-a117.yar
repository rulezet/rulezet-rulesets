rule TTP_XOR_WriteProcessMemory_a117 {
  strings:
    $key_a117 = { f6 65 [2] c4 47 [2] c2 72 [2] ec 72 [2] d3 6e }

  condition:
    any of them
}