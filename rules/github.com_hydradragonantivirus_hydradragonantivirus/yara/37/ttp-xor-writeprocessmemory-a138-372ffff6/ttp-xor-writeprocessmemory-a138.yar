rule TTP_XOR_WriteProcessMemory_a138 {
  strings:
    $key_a138 = { f6 4a [2] c4 68 [2] c2 5d [2] ec 5d [2] d3 41 }

  condition:
    any of them
}