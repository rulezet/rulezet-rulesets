rule TTP_XOR_WriteProcessMemory_fe7f {
  strings:
    $key_fe7f = { a9 0d [2] 9b 2f [2] 9d 1a [2] b3 1a [2] 8c 06 }

  condition:
    any of them
}