rule TTP_XOR_WriteProcessMemory_fe7d {
  strings:
    $key_fe7d = { a9 0f [2] 9b 2d [2] 9d 18 [2] b3 18 [2] 8c 04 }

  condition:
    any of them
}