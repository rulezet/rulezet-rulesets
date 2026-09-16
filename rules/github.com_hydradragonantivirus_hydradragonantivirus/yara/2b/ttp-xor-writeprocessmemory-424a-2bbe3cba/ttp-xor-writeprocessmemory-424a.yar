rule TTP_XOR_WriteProcessMemory_424a {
  strings:
    $key_424a = { 15 38 [2] 27 1a [2] 21 2f [2] 0f 2f [2] 30 33 }

  condition:
    any of them
}