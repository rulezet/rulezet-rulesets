rule TTP_XOR_WriteProcessMemory_a6ca {
  strings:
    $key_a6ca = { f1 b8 [2] c3 9a [2] c5 af [2] eb af [2] d4 b3 }

  condition:
    any of them
}