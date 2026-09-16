rule TTP_XOR_WriteProcessMemory_644a {
  strings:
    $key_644a = { 33 38 [2] 01 1a [2] 07 2f [2] 29 2f [2] 16 33 }

  condition:
    any of them
}