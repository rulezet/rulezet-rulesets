rule TTP_XOR_WriteProcessMemory_631f {
  strings:
    $key_631f = { 34 6d [2] 06 4f [2] 00 7a [2] 2e 7a [2] 11 66 }

  condition:
    any of them
}