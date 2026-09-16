rule TTP_XOR_WriteProcessMemory_a518 {
  strings:
    $key_a518 = { f2 6a [2] c0 48 [2] c6 7d [2] e8 7d [2] d7 61 }

  condition:
    any of them
}