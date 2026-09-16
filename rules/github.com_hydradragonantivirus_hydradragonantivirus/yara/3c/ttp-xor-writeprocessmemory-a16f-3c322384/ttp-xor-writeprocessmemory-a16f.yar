rule TTP_XOR_WriteProcessMemory_a16f {
  strings:
    $key_a16f = { f6 1d [2] c4 3f [2] c2 0a [2] ec 0a [2] d3 16 }

  condition:
    any of them
}