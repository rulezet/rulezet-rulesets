rule TTP_XOR_WriteProcessMemory_a15f {
  strings:
    $key_a15f = { f6 2d [2] c4 0f [2] c2 3a [2] ec 3a [2] d3 26 }

  condition:
    any of them
}