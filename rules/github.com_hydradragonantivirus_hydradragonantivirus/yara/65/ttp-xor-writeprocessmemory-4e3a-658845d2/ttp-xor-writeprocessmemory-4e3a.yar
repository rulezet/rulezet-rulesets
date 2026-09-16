rule TTP_XOR_WriteProcessMemory_4e3a {
  strings:
    $key_4e3a = { 19 48 [2] 2b 6a [2] 2d 5f [2] 03 5f [2] 3c 43 }

  condition:
    any of them
}