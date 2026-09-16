rule TTP_XOR_WriteProcessMemory_a6e9 {
  strings:
    $key_a6e9 = { f1 9b [2] c3 b9 [2] c5 8c [2] eb 8c [2] d4 90 }

  condition:
    any of them
}