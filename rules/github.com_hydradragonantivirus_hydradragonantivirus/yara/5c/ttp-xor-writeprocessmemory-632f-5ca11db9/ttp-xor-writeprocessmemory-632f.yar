rule TTP_XOR_WriteProcessMemory_632f {
  strings:
    $key_632f = { 34 5d [2] 06 7f [2] 00 4a [2] 2e 4a [2] 11 56 }

  condition:
    any of them
}