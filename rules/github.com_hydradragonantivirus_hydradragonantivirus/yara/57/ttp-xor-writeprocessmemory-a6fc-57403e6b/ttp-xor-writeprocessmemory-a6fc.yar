rule TTP_XOR_WriteProcessMemory_a6fc {
  strings:
    $key_a6fc = { f1 8e [2] c3 ac [2] c5 99 [2] eb 99 [2] d4 85 }

  condition:
    any of them
}