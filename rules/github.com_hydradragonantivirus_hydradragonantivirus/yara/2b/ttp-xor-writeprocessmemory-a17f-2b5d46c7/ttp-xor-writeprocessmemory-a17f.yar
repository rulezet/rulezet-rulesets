rule TTP_XOR_WriteProcessMemory_a17f {
  strings:
    $key_a17f = { f6 0d [2] c4 2f [2] c2 1a [2] ec 1a [2] d3 06 }

  condition:
    any of them
}