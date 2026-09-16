rule TTP_XOR_WriteProcessMemory_a1ce {
  strings:
    $key_a1ce = { f6 bc [2] c4 9e [2] c2 ab [2] ec ab [2] d3 b7 }

  condition:
    any of them
}