rule TTP_XOR_WriteProcessMemory_a13e {
  strings:
    $key_a13e = { f6 4c [2] c4 6e [2] c2 5b [2] ec 5b [2] d3 47 }

  condition:
    any of them
}