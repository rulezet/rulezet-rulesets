rule TTP_XOR_WriteProcessMemory_0b2a {
  strings:
    $key_0b2a = { 5c 58 [2] 6e 7a [2] 68 4f [2] 46 4f [2] 79 53 }

  condition:
    any of them
}