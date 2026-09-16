rule TTP_XOR_WriteProcessMemory_a018 {
  strings:
    $key_a018 = { f7 6a [2] c5 48 [2] c3 7d [2] ed 7d [2] d2 61 }

  condition:
    any of them
}