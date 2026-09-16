rule TTP_XOR_WriteProcessMemory_a7ef {
  strings:
    $key_a7ef = { f0 9d [2] c2 bf [2] c4 8a [2] ea 8a [2] d5 96 }

  condition:
    any of them
}