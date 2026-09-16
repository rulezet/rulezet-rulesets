rule TTP_XOR_WriteProcessMemory_5c1f {
  strings:
    $key_5c1f = { 0b 6d [2] 39 4f [2] 3f 7a [2] 11 7a [2] 2e 66 }

  condition:
    any of them
}