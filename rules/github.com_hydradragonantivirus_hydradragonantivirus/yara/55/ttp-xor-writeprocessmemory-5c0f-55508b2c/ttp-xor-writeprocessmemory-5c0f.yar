rule TTP_XOR_WriteProcessMemory_5c0f {
  strings:
    $key_5c0f = { 0b 7d [2] 39 5f [2] 3f 6a [2] 11 6a [2] 2e 76 }

  condition:
    any of them
}