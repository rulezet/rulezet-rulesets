rule TTP_XOR_WriteProcessMemory_a12d {
  strings:
    $key_a12d = { f6 5f [2] c4 7d [2] c2 48 [2] ec 48 [2] d3 54 }

  condition:
    any of them
}