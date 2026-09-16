rule TTP_XOR_WriteProcessMemory_4d2f {
  strings:
    $key_4d2f = { 1a 5d [2] 28 7f [2] 2e 4a [2] 00 4a [2] 3f 56 }

  condition:
    any of them
}