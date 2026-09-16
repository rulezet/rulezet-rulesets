rule TTP_XOR_WriteProcessMemory_ff5f {
  strings:
    $key_ff5f = { a8 2d [2] 9a 0f [2] 9c 3a [2] b2 3a [2] 8d 26 }

  condition:
    any of them
}