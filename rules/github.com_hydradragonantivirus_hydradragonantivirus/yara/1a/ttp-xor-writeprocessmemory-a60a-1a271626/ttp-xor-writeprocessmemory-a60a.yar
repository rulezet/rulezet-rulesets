rule TTP_XOR_WriteProcessMemory_a60a {
  strings:
    $key_a60a = { f1 78 [2] c3 5a [2] c5 6f [2] eb 6f [2] d4 73 }

  condition:
    any of them
}