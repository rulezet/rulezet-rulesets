rule TTP_XOR_WriteProcessMemory_5c2f {
  strings:
    $key_5c2f = { 0b 5d [2] 39 7f [2] 3f 4a [2] 11 4a [2] 2e 56 }

  condition:
    any of them
}