rule TTP_XOR_WriteProcessMemory_324a {
  strings:
    $key_324a = { 65 38 [2] 57 1a [2] 51 2f [2] 7f 2f [2] 40 33 }

  condition:
    any of them
}