rule TTP_XOR_WriteProcessMemory_a108 {
  strings:
    $key_a108 = { f6 7a [2] c4 58 [2] c2 6d [2] ec 6d [2] d3 71 }

  condition:
    any of them
}