rule TTP_XOR_WriteProcessMemory_a41b {
  strings:
    $key_a41b = { f3 69 [2] c1 4b [2] c7 7e [2] e9 7e [2] d6 62 }

  condition:
    any of them
}