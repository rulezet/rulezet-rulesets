rule TTP_XOR_WriteProcessMemory_7a5a {
  strings:
    $key_7a5a = { 2d 28 [2] 1f 0a [2] 19 3f [2] 37 3f [2] 08 23 }

  condition:
    any of them
}