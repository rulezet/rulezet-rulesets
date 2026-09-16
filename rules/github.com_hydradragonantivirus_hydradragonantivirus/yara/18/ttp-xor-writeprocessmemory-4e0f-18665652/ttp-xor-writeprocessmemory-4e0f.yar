rule TTP_XOR_WriteProcessMemory_4e0f {
  strings:
    $key_4e0f = { 19 7d [2] 2b 5f [2] 2d 6a [2] 03 6a [2] 3c 76 }

  condition:
    any of them
}