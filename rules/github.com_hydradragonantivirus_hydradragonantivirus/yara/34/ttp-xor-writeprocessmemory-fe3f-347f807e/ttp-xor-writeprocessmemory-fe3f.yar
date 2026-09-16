rule TTP_XOR_WriteProcessMemory_fe3f {
  strings:
    $key_fe3f = { a9 4d [2] 9b 6f [2] 9d 5a [2] b3 5a [2] 8c 46 }

  condition:
    any of them
}