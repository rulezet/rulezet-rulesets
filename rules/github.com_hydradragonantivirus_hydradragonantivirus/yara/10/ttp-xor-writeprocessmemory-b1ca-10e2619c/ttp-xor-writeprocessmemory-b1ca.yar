rule TTP_XOR_WriteProcessMemory_b1ca {
  strings:
    $key_b1ca = { e6 b8 [2] d4 9a [2] d2 af [2] fc af [2] c3 b3 }

  condition:
    any of them
}