rule TTP_XOR_WriteProcessMemory_7a4a {
  strings:
    $key_7a4a = { 2d 38 [2] 1f 1a [2] 19 2f [2] 37 2f [2] 08 33 }

  condition:
    any of them
}