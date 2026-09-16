rule TTP_XOR_WriteProcessMemory_425f {
  strings:
    $key_425f = { 15 2d [2] 27 0f [2] 21 3a [2] 0f 3a [2] 30 26 }

  condition:
    any of them
}