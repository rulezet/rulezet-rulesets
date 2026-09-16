rule TTP_XOR_WriteProcessMemory_a51a {
  strings:
    $key_a51a = { f2 68 [2] c0 4a [2] c6 7f [2] e8 7f [2] d7 63 }

  condition:
    any of them
}