rule TTP_XOR_WriteProcessMemory_4e38 {
  strings:
    $key_4e38 = { 19 4a [2] 2b 68 [2] 2d 5d [2] 03 5d [2] 3c 41 }

  condition:
    any of them
}