rule TTP_XOR_WriteProcessMemory_a61b {
  strings:
    $key_a61b = { f1 69 [2] c3 4b [2] c5 7e [2] eb 7e [2] d4 62 }

  condition:
    any of them
}