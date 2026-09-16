rule TTP_XOR_WriteProcessMemory_a13f {
  strings:
    $key_a13f = { f6 4d [2] c4 6f [2] c2 5a [2] ec 5a [2] d3 46 }

  condition:
    any of them
}