rule TTP_XOR_WriteProcessMemory_a76a {
  strings:
    $key_a76a = { f0 18 [2] c2 3a [2] c4 0f [2] ea 0f [2] d5 13 }

  condition:
    any of them
}