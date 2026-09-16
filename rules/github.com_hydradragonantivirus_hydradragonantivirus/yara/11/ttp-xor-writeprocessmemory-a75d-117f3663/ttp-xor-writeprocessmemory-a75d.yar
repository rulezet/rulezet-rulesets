rule TTP_XOR_WriteProcessMemory_a75d {
  strings:
    $key_a75d = { f0 2f [2] c2 0d [2] c4 38 [2] ea 38 [2] d5 24 }

  condition:
    any of them
}