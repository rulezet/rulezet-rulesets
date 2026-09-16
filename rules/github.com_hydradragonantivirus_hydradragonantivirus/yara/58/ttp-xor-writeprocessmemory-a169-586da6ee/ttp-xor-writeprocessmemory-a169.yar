rule TTP_XOR_WriteProcessMemory_a169 {
  strings:
    $key_a169 = { f6 1b [2] c4 39 [2] c2 0c [2] ec 0c [2] d3 10 }

  condition:
    any of them
}