rule TTP_XOR_WriteProcessMemory_8e7a {
  strings:
    $key_8e7a = { d9 08 [2] eb 2a [2] ed 1f [2] c3 1f [2] fc 03 }

  condition:
    any of them
}