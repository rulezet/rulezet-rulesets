rule TTP_XOR_WriteProcessMemory_a12a {
  strings:
    $key_a12a = { f6 58 [2] c4 7a [2] c2 4f [2] ec 4f [2] d3 53 }

  condition:
    any of them
}