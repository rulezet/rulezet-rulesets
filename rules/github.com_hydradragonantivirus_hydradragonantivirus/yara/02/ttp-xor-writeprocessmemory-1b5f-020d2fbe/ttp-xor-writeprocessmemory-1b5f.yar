rule TTP_XOR_WriteProcessMemory_1b5f {
  strings:
    $key_1b5f = { 4c 2d [2] 7e 0f [2] 78 3a [2] 56 3a [2] 69 26 }

  condition:
    any of them
}