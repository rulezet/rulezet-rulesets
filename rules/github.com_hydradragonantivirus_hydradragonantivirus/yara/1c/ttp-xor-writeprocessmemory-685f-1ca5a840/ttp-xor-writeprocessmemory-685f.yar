rule TTP_XOR_WriteProcessMemory_685f {
  strings:
    $key_685f = { 3f 2d [2] 0d 0f [2] 0b 3a [2] 25 3a [2] 1a 26 }

  condition:
    any of them
}