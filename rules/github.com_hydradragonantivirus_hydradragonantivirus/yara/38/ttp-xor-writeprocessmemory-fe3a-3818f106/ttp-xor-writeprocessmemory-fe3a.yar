rule TTP_XOR_WriteProcessMemory_fe3a {
  strings:
    $key_fe3a = { a9 48 [2] 9b 6a [2] 9d 5f [2] b3 5f [2] 8c 43 }

  condition:
    any of them
}