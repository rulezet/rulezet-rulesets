rule TTP_XOR_WriteProcessMemory_1a4a {
  strings:
    $key_1a4a = { 4d 38 [2] 7f 1a [2] 79 2f [2] 57 2f [2] 68 33 }

  condition:
    any of them
}