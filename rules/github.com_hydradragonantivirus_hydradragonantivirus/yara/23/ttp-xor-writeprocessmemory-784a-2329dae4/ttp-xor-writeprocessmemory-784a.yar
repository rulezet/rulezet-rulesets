rule TTP_XOR_WriteProcessMemory_784a {
  strings:
    $key_784a = { 2f 38 [2] 1d 1a [2] 1b 2f [2] 35 2f [2] 0a 33 }

  condition:
    any of them
}