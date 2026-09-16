rule TTP_XOR_WriteProcessMemory_7a6a {
  strings:
    $key_7a6a = { 2d 18 [2] 1f 3a [2] 19 0f [2] 37 0f [2] 08 13 }

  condition:
    any of them
}