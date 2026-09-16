rule TTP_XOR_WriteProcessMemory_2a5f {
  strings:
    $key_2a5f = { 7d 2d [2] 4f 0f [2] 49 3a [2] 67 3a [2] 58 26 }

  condition:
    any of them
}