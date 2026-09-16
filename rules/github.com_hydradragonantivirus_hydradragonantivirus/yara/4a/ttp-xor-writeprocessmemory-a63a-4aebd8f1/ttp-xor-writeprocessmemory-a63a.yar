rule TTP_XOR_WriteProcessMemory_a63a {
  strings:
    $key_a63a = { f1 48 [2] c3 6a [2] c5 5f [2] eb 5f [2] d4 43 }

  condition:
    any of them
}