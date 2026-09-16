rule TTP_XOR_WriteProcessMemory_fe0a {
  strings:
    $key_fe0a = { a9 78 [2] 9b 5a [2] 9d 6f [2] b3 6f [2] 8c 73 }

  condition:
    any of them
}