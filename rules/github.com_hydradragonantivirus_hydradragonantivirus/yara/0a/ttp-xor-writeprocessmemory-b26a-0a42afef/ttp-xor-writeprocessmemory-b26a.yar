rule TTP_XOR_WriteProcessMemory_b26a {
  strings:
    $key_b26a = { e5 18 [2] d7 3a [2] d1 0f [2] ff 0f [2] c0 13 }

  condition:
    any of them
}