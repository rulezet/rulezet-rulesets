rule TTP_XOR_WriteProcessMemory_8e7f {
  strings:
    $key_8e7f = { d9 0d [2] eb 2f [2] ed 1a [2] c3 1a [2] fc 06 }

  condition:
    any of them
}