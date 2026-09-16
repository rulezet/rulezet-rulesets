rule TTP_XOR_WriteProcessMemory_a17b {
  strings:
    $key_a17b = { f6 09 [2] c4 2b [2] c2 1e [2] ec 1e [2] d3 02 }

  condition:
    any of them
}