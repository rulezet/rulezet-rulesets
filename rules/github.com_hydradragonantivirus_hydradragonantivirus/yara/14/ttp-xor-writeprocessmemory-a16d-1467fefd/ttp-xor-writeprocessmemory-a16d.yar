rule TTP_XOR_WriteProcessMemory_a16d {
  strings:
    $key_a16d = { f6 1f [2] c4 3d [2] c2 08 [2] ec 08 [2] d3 14 }

  condition:
    any of them
}