rule TTP_XOR_WriteProcessMemory_a4e9 {
  strings:
    $key_a4e9 = { f3 9b [2] c1 b9 [2] c7 8c [2] e9 8c [2] d6 90 }

  condition:
    any of them
}