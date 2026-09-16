rule TTP_XOR_WriteProcessMemory_b26f {
  strings:
    $key_b26f = { e5 1d [2] d7 3f [2] d1 0a [2] ff 0a [2] c0 16 }

  condition:
    any of them
}