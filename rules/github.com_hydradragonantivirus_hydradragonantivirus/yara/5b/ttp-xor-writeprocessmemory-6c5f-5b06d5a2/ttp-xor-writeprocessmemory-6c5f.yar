rule TTP_XOR_WriteProcessMemory_6c5f {
  strings:
    $key_6c5f = { 3b 2d [2] 09 0f [2] 0f 3a [2] 21 3a [2] 1e 26 }

  condition:
    any of them
}