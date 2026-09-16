rule TTP_XOR_WriteProcessMemory_4ef8 {
  strings:
    $key_4ef8 = { 19 8a [2] 2b a8 [2] 2d 9d [2] 03 9d [2] 3c 81 }

  condition:
    any of them
}