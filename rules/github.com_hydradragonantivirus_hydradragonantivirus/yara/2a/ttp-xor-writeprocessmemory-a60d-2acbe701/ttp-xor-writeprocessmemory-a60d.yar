rule TTP_XOR_WriteProcessMemory_a60d {
  strings:
    $key_a60d = { f1 7f [2] c3 5d [2] c5 68 [2] eb 68 [2] d4 74 }

  condition:
    any of them
}