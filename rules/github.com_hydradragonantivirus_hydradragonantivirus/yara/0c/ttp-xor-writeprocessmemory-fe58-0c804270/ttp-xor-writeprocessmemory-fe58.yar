rule TTP_XOR_WriteProcessMemory_fe58 {
  strings:
    $key_fe58 = { a9 2a [2] 9b 08 [2] 9d 3d [2] b3 3d [2] 8c 21 }

  condition:
    any of them
}