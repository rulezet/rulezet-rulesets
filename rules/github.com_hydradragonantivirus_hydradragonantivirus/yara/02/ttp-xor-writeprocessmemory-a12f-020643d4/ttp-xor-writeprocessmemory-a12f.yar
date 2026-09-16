rule TTP_XOR_WriteProcessMemory_a12f {
  strings:
    $key_a12f = { f6 5d [2] c4 7f [2] c2 4a [2] ec 4a [2] d3 56 }

  condition:
    any of them
}