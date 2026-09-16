rule TTP_XOR_WriteProcessMemory_8e2f {
  strings:
    $key_8e2f = { d9 5d [2] eb 7f [2] ed 4a [2] c3 4a [2] fc 56 }

  condition:
    any of them
}