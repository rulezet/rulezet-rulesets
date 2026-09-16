rule TTP_XOR_WriteProcessMemory_b328 {
  strings:
    $key_b328 = { e4 5a [2] d6 78 [2] d0 4d [2] fe 4d [2] c1 51 }

  condition:
    any of them
}