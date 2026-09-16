rule TTP_XOR_WriteProcessMemory_a13d {
  strings:
    $key_a13d = { f6 4f [2] c4 6d [2] c2 58 [2] ec 58 [2] d3 44 }

  condition:
    any of them
}