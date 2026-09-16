rule TTP_XOR_WriteProcessMemory_fe6f {
  strings:
    $key_fe6f = { a9 1d [2] 9b 3f [2] 9d 0a [2] b3 0a [2] 8c 16 }

  condition:
    any of them
}