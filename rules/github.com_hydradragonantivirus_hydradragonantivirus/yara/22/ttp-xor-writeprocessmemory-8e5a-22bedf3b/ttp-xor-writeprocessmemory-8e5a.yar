rule TTP_XOR_WriteProcessMemory_8e5a {
  strings:
    $key_8e5a = { d9 28 [2] eb 0a [2] ed 3f [2] c3 3f [2] fc 23 }

  condition:
    any of them
}