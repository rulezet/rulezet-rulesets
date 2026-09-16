rule TTP_XOR_WriteProcessMemory_5f3f {
  strings:
    $key_5f3f = { 08 4d [2] 3a 6f [2] 3c 5a [2] 12 5a [2] 2d 46 }

  condition:
    any of them
}