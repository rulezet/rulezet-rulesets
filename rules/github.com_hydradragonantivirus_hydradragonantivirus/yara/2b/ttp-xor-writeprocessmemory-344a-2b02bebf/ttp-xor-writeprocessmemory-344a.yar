rule TTP_XOR_WriteProcessMemory_344a {
  strings:
    $key_344a = { 63 38 [2] 51 1a [2] 57 2f [2] 79 2f [2] 46 33 }

  condition:
    any of them
}