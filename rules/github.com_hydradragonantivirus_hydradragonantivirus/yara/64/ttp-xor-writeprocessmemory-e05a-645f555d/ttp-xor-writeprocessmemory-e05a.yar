rule TTP_XOR_WriteProcessMemory_e05a {
  strings:
    $key_e05a = { b7 28 [2] 85 0a [2] 83 3f [2] ad 3f [2] 92 23 }

  condition:
    any of them
}