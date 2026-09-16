rule TTP_XOR_WriteProcessMemory_5c5f {
  strings:
    $key_5c5f = { 0b 2d [2] 39 0f [2] 3f 3a [2] 11 3a [2] 2e 26 }

  condition:
    any of them
}