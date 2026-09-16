rule TTP_XOR_WriteProcessMemory_5f2a {
  strings:
    $key_5f2a = { 08 58 [2] 3a 7a [2] 3c 4f [2] 12 4f [2] 2d 53 }

  condition:
    any of them
}