rule TTP_XOR_WriteProcessMemory_fe18 {
  strings:
    $key_fe18 = { a9 6a [2] 9b 48 [2] 9d 7d [2] b3 7d [2] 8c 61 }

  condition:
    any of them
}