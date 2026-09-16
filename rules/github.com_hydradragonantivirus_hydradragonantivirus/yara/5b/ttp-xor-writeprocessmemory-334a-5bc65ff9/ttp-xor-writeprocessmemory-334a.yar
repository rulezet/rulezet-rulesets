rule TTP_XOR_WriteProcessMemory_334a {
  strings:
    $key_334a = { 64 38 [2] 56 1a [2] 50 2f [2] 7e 2f [2] 41 33 }

  condition:
    any of them
}