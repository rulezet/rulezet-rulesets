rule TTP_XOR_WriteProcessMemory_a41a {
  strings:
    $key_a41a = { f3 68 [2] c1 4a [2] c7 7f [2] e9 7f [2] d6 63 }

  condition:
    any of them
}