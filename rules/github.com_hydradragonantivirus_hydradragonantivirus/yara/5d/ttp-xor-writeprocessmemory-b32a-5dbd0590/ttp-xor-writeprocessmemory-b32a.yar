rule TTP_XOR_WriteProcessMemory_b32a {
  strings:
    $key_b32a = { e4 58 [2] d6 7a [2] d0 4f [2] fe 4f [2] c1 53 }

  condition:
    any of them
}