rule TTP_XOR_WriteProcessMemory_4d0f {
  strings:
    $key_4d0f = { 1a 7d [2] 28 5f [2] 2e 6a [2] 00 6a [2] 3f 76 }

  condition:
    any of them
}