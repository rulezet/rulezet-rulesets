rule TTP_XOR_WriteProcessMemory_a060 {
  strings:
    $key_a060 = { f7 12 [2] c5 30 [2] c3 05 [2] ed 05 [2] d2 19 }

  condition:
    any of them
}