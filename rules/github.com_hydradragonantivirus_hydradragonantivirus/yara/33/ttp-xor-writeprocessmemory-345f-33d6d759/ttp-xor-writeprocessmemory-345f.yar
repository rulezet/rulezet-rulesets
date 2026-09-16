rule TTP_XOR_WriteProcessMemory_345f {
  strings:
    $key_345f = { 63 2d [2] 51 0f [2] 57 3a [2] 79 3a [2] 46 26 }

  condition:
    any of them
}