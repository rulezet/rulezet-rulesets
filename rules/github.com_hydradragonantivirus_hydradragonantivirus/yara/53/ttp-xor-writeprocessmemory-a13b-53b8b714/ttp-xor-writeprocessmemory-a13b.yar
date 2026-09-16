rule TTP_XOR_WriteProcessMemory_a13b {
  strings:
    $key_a13b = { f6 49 [2] c4 6b [2] c2 5e [2] ec 5e [2] d3 42 }

  condition:
    any of them
}