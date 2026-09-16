rule TTP_XOR_WriteProcessMemory_b25f {
  strings:
    $key_b25f = { e5 2d [2] d7 0f [2] d1 3a [2] ff 3a [2] c0 26 }

  condition:
    any of them
}