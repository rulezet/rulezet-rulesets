rule TTP_XOR_WriteProcessMemory_a45a {
  strings:
    $key_a45a = { f3 28 [2] c1 0a [2] c7 3f [2] e9 3f [2] d6 23 }

  condition:
    any of them
}