rule TTP_XOR_WriteProcessMemory_b34f {
  strings:
    $key_b34f = { e4 3d [2] d6 1f [2] d0 2a [2] fe 2a [2] c1 36 }

  condition:
    any of them
}