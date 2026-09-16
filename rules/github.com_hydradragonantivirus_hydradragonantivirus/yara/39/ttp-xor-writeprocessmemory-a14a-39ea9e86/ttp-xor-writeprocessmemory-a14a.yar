rule TTP_XOR_WriteProcessMemory_a14a {
  strings:
    $key_a14a = { f6 38 [2] c4 1a [2] c2 2f [2] ec 2f [2] d3 33 }

  condition:
    any of them
}