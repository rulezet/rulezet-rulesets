rule TTP_XOR_WriteProcessMemory_7a7a {
  strings:
    $key_7a7a = { 2d 08 [2] 1f 2a [2] 19 1f [2] 37 1f [2] 08 03 }

  condition:
    any of them
}