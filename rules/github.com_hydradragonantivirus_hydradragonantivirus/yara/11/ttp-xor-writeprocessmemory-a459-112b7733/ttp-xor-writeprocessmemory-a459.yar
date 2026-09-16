rule TTP_XOR_WriteProcessMemory_a459 {
  strings:
    $key_a459 = { f3 2b [2] c1 09 [2] c7 3c [2] e9 3c [2] d6 20 }

  condition:
    any of them
}