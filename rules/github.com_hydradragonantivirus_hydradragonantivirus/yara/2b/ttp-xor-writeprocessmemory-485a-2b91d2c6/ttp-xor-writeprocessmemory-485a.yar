rule TTP_XOR_WriteProcessMemory_485a {
  strings:
    $key_485a = { 1f 28 [2] 2d 0a [2] 2b 3f [2] 05 3f [2] 3a 23 }

  condition:
    any of them
}