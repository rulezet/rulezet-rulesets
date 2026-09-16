rule TTP_XOR_WriteProcessMemory_b77a {
  strings:
    $key_b77a = { e0 08 [2] d2 2a [2] d4 1f [2] fa 1f [2] c5 03 }

  condition:
    any of them
}