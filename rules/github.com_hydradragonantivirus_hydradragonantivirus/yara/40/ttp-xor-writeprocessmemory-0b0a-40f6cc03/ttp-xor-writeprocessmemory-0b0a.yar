rule TTP_XOR_WriteProcessMemory_0b0a {
  strings:
    $key_0b0a = { 5c 78 [2] 6e 5a [2] 68 6f [2] 46 6f [2] 79 73 }

  condition:
    any of them
}