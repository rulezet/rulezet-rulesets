rule TTP_XOR_WriteProcessMemory_a5e9 {
  strings:
    $key_a5e9 = { f2 9b [2] c0 b9 [2] c6 8c [2] e8 8c [2] d7 90 }

  condition:
    any of them
}