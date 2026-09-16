rule TTP_XOR_WriteProcessMemory_b25a {
  strings:
    $key_b25a = { e5 28 [2] d7 0a [2] d1 3f [2] ff 3f [2] c0 23 }

  condition:
    any of them
}