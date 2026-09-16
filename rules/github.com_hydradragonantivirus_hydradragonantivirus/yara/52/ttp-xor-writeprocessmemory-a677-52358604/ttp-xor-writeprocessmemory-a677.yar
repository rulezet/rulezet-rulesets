rule TTP_XOR_WriteProcessMemory_a677 {
  strings:
    $key_a677 = { f1 05 [2] c3 27 [2] c5 12 [2] eb 12 [2] d4 0e }

  condition:
    any of them
}