rule TTP_XOR_WriteProcessMemory_0b1a {
  strings:
    $key_0b1a = { 5c 68 [2] 6e 4a [2] 68 7f [2] 46 7f [2] 79 63 }

  condition:
    any of them
}