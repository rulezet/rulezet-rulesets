rule TTP_XOR_WriteProcessMemory_a45c {
  strings:
    $key_a45c = { f3 2e [2] c1 0c [2] c7 39 [2] e9 39 [2] d6 25 }

  condition:
    any of them
}