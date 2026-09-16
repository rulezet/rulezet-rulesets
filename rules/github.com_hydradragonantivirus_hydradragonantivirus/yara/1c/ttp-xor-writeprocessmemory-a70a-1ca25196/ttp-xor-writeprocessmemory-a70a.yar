rule TTP_XOR_WriteProcessMemory_a70a {
  strings:
    $key_a70a = { f0 78 [2] c2 5a [2] c4 6f [2] ea 6f [2] d5 73 }

  condition:
    any of them
}