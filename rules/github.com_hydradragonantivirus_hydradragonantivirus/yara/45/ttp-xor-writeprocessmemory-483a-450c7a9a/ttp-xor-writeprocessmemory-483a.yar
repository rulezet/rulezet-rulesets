rule TTP_XOR_WriteProcessMemory_483a {
  strings:
    $key_483a = { 1f 48 [2] 2d 6a [2] 2b 5f [2] 05 5f [2] 3a 43 }

  condition:
    any of them
}