rule TTP_XOR_WriteProcessMemory_fe4a {
  strings:
    $key_fe4a = { a9 38 [2] 9b 1a [2] 9d 2f [2] b3 2f [2] 8c 33 }

  condition:
    any of them
}