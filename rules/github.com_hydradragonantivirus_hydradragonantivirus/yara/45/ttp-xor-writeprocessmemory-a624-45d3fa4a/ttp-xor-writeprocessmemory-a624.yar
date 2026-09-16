rule TTP_XOR_WriteProcessMemory_a624 {
  strings:
    $key_a624 = { f1 56 [2] c3 74 [2] c5 41 [2] eb 41 [2] d4 5d }

  condition:
    any of them
}