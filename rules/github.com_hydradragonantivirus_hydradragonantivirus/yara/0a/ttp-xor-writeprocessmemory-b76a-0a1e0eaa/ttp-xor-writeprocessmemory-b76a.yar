rule TTP_XOR_WriteProcessMemory_b76a {
  strings:
    $key_b76a = { e0 18 [2] d2 3a [2] d4 0f [2] fa 0f [2] c5 13 }

  condition:
    any of them
}