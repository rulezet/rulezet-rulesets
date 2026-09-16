rule TTP_XOR_WriteProcessMemory_481a {
  strings:
    $key_481a = { 1f 68 [2] 2d 4a [2] 2b 7f [2] 05 7f [2] 3a 63 }

  condition:
    any of them
}