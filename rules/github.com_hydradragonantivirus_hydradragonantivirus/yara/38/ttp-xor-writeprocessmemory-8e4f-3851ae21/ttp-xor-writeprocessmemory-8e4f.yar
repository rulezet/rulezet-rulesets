rule TTP_XOR_WriteProcessMemory_8e4f {
  strings:
    $key_8e4f = { d9 3d [2] eb 1f [2] ed 2a [2] c3 2a [2] fc 36 }

  condition:
    any of them
}