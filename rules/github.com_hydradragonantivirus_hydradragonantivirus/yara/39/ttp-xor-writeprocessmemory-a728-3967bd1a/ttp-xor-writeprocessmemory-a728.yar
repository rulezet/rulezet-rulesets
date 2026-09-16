rule TTP_XOR_WriteProcessMemory_a728 {
  strings:
    $key_a728 = { f0 5a [2] c2 78 [2] c4 4d [2] ea 4d [2] d5 51 }

  condition:
    any of them
}