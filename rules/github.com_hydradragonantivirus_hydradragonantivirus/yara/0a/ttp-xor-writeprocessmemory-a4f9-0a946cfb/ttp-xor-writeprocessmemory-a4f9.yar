rule TTP_XOR_WriteProcessMemory_a4f9 {
  strings:
    $key_a4f9 = { f3 8b [2] c1 a9 [2] c7 9c [2] e9 9c [2] d6 80 }

  condition:
    any of them
}