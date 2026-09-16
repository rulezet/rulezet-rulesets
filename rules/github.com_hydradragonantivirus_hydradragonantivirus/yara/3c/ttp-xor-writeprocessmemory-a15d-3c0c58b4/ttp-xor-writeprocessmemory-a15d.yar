rule TTP_XOR_WriteProcessMemory_a15d {
  strings:
    $key_a15d = { f6 2f [2] c4 0d [2] c2 38 [2] ec 38 [2] d3 24 }

  condition:
    any of them
}