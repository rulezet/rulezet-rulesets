rule TTP_XOR_WriteProcessMemory_a23a {
  strings:
    $key_a23a = { f5 48 [2] c7 6a [2] c1 5f [2] ef 5f [2] d0 43 }

  condition:
    any of them
}