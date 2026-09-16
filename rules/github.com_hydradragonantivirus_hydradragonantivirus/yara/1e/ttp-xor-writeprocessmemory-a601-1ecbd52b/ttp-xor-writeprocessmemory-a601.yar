rule TTP_XOR_WriteProcessMemory_a601 {
  strings:
    $key_a601 = { f1 73 [2] c3 51 [2] c5 64 [2] eb 64 [2] d4 78 }

  condition:
    any of them
}