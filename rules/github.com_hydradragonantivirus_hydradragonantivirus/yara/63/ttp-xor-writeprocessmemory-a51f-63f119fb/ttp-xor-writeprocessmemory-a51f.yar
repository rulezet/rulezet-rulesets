rule TTP_XOR_WriteProcessMemory_a51f {
  strings:
    $key_a51f = { f2 6d [2] c0 4f [2] c6 7a [2] e8 7a [2] d7 66 }

  condition:
    any of them
}