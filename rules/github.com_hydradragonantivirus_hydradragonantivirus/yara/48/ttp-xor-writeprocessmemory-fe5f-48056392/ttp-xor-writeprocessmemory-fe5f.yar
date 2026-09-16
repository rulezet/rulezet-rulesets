rule TTP_XOR_WriteProcessMemory_fe5f {
  strings:
    $key_fe5f = { a9 2d [2] 9b 0f [2] 9d 3a [2] b3 3a [2] 8c 26 }

  condition:
    any of them
}