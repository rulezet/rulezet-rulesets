rule TTP_XOR_WriteProcessMemory_a674 {
  strings:
    $key_a674 = { f1 06 [2] c3 24 [2] c5 11 [2] eb 11 [2] d4 0d }

  condition:
    any of them
}