rule TTP_XOR_WriteProcessMemory_5a4a {
  strings:
    $key_5a4a = { 0d 38 [2] 3f 1a [2] 39 2f [2] 17 2f [2] 28 33 }

  condition:
    any of them
}