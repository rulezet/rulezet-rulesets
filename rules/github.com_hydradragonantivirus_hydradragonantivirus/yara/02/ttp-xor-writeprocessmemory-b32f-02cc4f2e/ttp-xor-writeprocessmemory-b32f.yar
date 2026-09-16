rule TTP_XOR_WriteProcessMemory_b32f {
  strings:
    $key_b32f = { e4 5d [2] d6 7f [2] d0 4a [2] fe 4a [2] c1 56 }

  condition:
    any of them
}