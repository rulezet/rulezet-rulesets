rule TTP_XOR_WriteProcessMemory_a428 {
  strings:
    $key_a428 = { f3 5a [2] c1 78 [2] c7 4d [2] e9 4d [2] d6 51 }

  condition:
    any of them
}