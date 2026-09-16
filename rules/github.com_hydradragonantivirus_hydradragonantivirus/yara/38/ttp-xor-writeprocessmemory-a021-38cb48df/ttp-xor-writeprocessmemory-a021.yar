rule TTP_XOR_WriteProcessMemory_a021 {
  strings:
    $key_a021 = { f7 53 [2] c5 71 [2] c3 44 [2] ed 44 [2] d2 58 }

  condition:
    any of them
}