rule TTP_XOR_WriteProcessMemory_0b4a {
  strings:
    $key_0b4a = { 5c 38 [2] 6e 1a [2] 68 2f [2] 46 2f [2] 79 33 }

  condition:
    any of them
}