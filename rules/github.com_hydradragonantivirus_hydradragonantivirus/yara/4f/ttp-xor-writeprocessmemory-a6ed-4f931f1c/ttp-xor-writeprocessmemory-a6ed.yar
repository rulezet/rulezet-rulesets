rule TTP_XOR_WriteProcessMemory_a6ed {
  strings:
    $key_a6ed = { f1 9f [2] c3 bd [2] c5 88 [2] eb 88 [2] d4 94 }

  condition:
    any of them
}