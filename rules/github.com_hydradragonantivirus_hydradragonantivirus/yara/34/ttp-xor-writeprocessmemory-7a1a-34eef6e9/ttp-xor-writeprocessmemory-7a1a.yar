rule TTP_XOR_WriteProcessMemory_7a1a {
  strings:
    $key_7a1a = { 2d 68 [2] 1f 4a [2] 19 7f [2] 37 7f [2] 08 63 }

  condition:
    any of them
}