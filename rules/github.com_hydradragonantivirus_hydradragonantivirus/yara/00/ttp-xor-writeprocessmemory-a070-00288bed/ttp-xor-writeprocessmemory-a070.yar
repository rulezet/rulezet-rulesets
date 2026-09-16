rule TTP_XOR_WriteProcessMemory_a070 {
  strings:
    $key_a070 = { f7 02 [2] c5 20 [2] c3 15 [2] ed 15 [2] d2 09 }

  condition:
    any of them
}