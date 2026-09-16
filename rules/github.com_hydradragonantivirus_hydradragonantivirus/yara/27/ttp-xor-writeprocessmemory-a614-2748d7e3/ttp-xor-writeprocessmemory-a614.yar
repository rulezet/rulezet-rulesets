rule TTP_XOR_WriteProcessMemory_a614 {
  strings:
    $key_a614 = { f1 66 [2] c3 44 [2] c5 71 [2] eb 71 [2] d4 6d }

  condition:
    any of them
}