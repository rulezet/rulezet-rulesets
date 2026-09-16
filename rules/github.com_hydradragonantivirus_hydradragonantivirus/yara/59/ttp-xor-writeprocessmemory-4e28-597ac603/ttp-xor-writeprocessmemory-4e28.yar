rule TTP_XOR_WriteProcessMemory_4e28 {
  strings:
    $key_4e28 = { 19 5a [2] 2b 78 [2] 2d 4d [2] 03 4d [2] 3c 51 }

  condition:
    any of them
}