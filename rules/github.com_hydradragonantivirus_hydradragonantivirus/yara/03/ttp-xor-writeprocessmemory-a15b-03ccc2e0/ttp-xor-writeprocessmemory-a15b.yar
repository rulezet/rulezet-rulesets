rule TTP_XOR_WriteProcessMemory_a15b {
  strings:
    $key_a15b = { f6 29 [2] c4 0b [2] c2 3e [2] ec 3e [2] d3 22 }

  condition:
    any of them
}