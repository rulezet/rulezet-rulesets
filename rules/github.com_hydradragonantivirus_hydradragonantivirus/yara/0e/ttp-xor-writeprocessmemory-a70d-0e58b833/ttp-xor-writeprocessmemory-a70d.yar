rule TTP_XOR_WriteProcessMemory_a70d {
  strings:
    $key_a70d = { f0 7f [2] c2 5d [2] c4 68 [2] ea 68 [2] d5 74 }

  condition:
    any of them
}