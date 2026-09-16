rule TTP_XOR_WriteProcessMemory_e95f {
  strings:
    $key_e95f = { be 2d [2] 8c 0f [2] 8a 3a [2] a4 3a [2] 9b 26 }

  condition:
    any of them
}