rule TTP_XOR_WriteProcessMemory_a14c {
  strings:
    $key_a14c = { f6 3e [2] c4 1c [2] c2 29 [2] ec 29 [2] d3 35 }

  condition:
    any of them
}