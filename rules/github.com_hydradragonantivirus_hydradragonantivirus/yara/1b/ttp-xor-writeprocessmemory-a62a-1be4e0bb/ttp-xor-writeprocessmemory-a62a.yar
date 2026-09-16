rule TTP_XOR_WriteProcessMemory_a62a {
  strings:
    $key_a62a = { f1 58 [2] c3 7a [2] c5 4f [2] eb 4f [2] d4 53 }

  condition:
    any of them
}