rule TTP_XOR_WriteProcessMemory_a038 {
  strings:
    $key_a038 = { f7 4a [2] c5 68 [2] c3 5d [2] ed 5d [2] d2 41 }

  condition:
    any of them
}