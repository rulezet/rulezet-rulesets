rule TTP_XOR_WriteProcessMemory_fe4f {
  strings:
    $key_fe4f = { a9 3d [2] 9b 1f [2] 9d 2a [2] b3 2a [2] 8c 36 }

  condition:
    any of them
}