rule TTP_XOR_WriteProcessMemory_5b2f {
  strings:
    $key_5b2f = { 0c 5d [2] 3e 7f [2] 38 4a [2] 16 4a [2] 29 56 }

  condition:
    any of them
}