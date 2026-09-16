rule TTP_XOR_WriteProcessMemory_fe6d {
  strings:
    $key_fe6d = { a9 1f [2] 9b 3d [2] 9d 08 [2] b3 08 [2] 8c 14 }

  condition:
    any of them
}