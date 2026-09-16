rule TTP_XOR_WriteProcessMemory_b14f {
  strings:
    $key_b14f = { e6 3d [2] d4 1f [2] d2 2a [2] fc 2a [2] c3 36 }

  condition:
    any of them
}