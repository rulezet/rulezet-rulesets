rule TTP_XOR_WriteProcessMemory_a438 {
  strings:
    $key_a438 = { f3 4a [2] c1 68 [2] c7 5d [2] e9 5d [2] d6 41 }

  condition:
    any of them
}