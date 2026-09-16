rule TTP_XOR_WriteProcessMemory_8e1f {
  strings:
    $key_8e1f = { d9 6d [2] eb 4f [2] ed 7a [2] c3 7a [2] fc 66 }

  condition:
    any of them
}