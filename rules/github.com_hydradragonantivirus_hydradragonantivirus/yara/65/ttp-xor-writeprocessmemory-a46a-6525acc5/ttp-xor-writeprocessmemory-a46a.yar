rule TTP_XOR_WriteProcessMemory_a46a {
  strings:
    $key_a46a = { f3 18 [2] c1 3a [2] c7 0f [2] e9 0f [2] d6 13 }

  condition:
    any of them
}