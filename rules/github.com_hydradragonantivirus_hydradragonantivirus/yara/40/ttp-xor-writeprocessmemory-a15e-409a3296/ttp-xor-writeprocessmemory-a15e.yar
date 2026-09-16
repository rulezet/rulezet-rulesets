rule TTP_XOR_WriteProcessMemory_a15e {
  strings:
    $key_a15e = { f6 2c [2] c4 0e [2] c2 3b [2] ec 3b [2] d3 27 }

  condition:
    any of them
}