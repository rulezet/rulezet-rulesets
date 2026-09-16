rule TTP_XOR_WriteProcessMemory_a538 {
  strings:
    $key_a538 = { f2 4a [2] c0 68 [2] c6 5d [2] e8 5d [2] d7 41 }

  condition:
    any of them
}