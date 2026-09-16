rule TTP_XOR_WriteProcessMemory_a67a {
  strings:
    $key_a67a = { f1 08 [2] c3 2a [2] c5 1f [2] eb 1f [2] d4 03 }

  condition:
    any of them
}