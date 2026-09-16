rule TTP_XOR_WriteProcessMemory_6d5f {
  strings:
    $key_6d5f = { 3a 2d [2] 08 0f [2] 0e 3a [2] 20 3a [2] 1f 26 }

  condition:
    any of them
}