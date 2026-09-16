rule TTP_XOR_WriteProcessMemory_fe0f {
  strings:
    $key_fe0f = { a9 7d [2] 9b 5f [2] 9d 6a [2] b3 6a [2] 8c 76 }

  condition:
    any of them
}