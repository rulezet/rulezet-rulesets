rule TTP_XOR_WriteProcessMemory_b22a {
  strings:
    $key_b22a = { e5 58 [2] d7 7a [2] d1 4f [2] ff 4f [2] c0 53 }

  condition:
    any of them
}