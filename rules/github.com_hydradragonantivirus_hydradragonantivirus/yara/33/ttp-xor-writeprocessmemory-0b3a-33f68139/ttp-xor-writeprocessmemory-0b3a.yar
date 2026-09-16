rule TTP_XOR_WriteProcessMemory_0b3a {
  strings:
    $key_0b3a = { 5c 48 [2] 6e 6a [2] 68 5f [2] 46 5f [2] 79 43 }

  condition:
    any of them
}