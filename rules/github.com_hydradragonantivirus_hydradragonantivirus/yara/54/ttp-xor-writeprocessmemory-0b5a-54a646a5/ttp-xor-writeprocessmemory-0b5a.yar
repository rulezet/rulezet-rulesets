rule TTP_XOR_WriteProcessMemory_0b5a {
  strings:
    $key_0b5a = { 5c 28 [2] 6e 0a [2] 68 3f [2] 46 3f [2] 79 23 }

  condition:
    any of them
}