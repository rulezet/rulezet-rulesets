rule TTP_XOR_WriteProcessMemory_4a5a {
  strings:
    $key_4a5a = { 1d 28 [2] 2f 0a [2] 29 3f [2] 07 3f [2] 38 23 }

  condition:
    any of them
}