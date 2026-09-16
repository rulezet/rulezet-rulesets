rule TTP_XOR_WriteProcessMemory_0c5f {
  strings:
    $key_0c5f = { 5b 2d [2] 69 0f [2] 6f 3a [2] 41 3a [2] 7e 26 }

  condition:
    any of them
}