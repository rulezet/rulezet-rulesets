rule TTP_XOR_WriteProcessMemory_a168 {
  strings:
    $key_a168 = { f6 1a [2] c4 38 [2] c2 0d [2] ec 0d [2] d3 11 }

  condition:
    any of them
}