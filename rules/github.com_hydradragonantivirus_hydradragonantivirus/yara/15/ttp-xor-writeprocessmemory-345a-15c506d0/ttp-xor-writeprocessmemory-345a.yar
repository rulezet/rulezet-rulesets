rule TTP_XOR_WriteProcessMemory_345a {
  strings:
    $key_345a = { 63 28 [2] 51 0a [2] 57 3f [2] 79 3f [2] 46 23 }

  condition:
    any of them
}