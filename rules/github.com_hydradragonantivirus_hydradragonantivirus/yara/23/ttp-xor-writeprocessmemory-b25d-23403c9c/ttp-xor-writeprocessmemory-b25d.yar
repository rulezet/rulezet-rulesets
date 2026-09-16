rule TTP_XOR_WriteProcessMemory_b25d {
  strings:
    $key_b25d = { e5 2f [2] d7 0d [2] d1 38 [2] ff 38 [2] c0 24 }

  condition:
    any of them
}