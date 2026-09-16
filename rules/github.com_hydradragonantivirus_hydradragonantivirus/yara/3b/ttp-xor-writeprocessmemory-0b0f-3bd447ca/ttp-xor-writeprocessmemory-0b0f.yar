rule TTP_XOR_WriteProcessMemory_0b0f {
  strings:
    $key_0b0f = { 5c 7d [2] 6e 5f [2] 68 6a [2] 46 6a [2] 79 76 }

  condition:
    any of them
}