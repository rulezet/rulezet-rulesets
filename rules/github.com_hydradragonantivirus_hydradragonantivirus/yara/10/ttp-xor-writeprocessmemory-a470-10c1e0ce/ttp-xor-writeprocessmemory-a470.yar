rule TTP_XOR_WriteProcessMemory_a470 {
  strings:
    $key_a470 = { f3 02 [2] c1 20 [2] c7 15 [2] e9 15 [2] d6 09 }

  condition:
    any of them
}