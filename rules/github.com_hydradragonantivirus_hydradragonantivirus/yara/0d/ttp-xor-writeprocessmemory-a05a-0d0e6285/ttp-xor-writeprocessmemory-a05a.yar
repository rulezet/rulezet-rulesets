rule TTP_XOR_WriteProcessMemory_a05a {
  strings:
    $key_a05a = { f7 28 [2] c5 0a [2] c3 3f [2] ed 3f [2] d2 23 }

  condition:
    any of them
}