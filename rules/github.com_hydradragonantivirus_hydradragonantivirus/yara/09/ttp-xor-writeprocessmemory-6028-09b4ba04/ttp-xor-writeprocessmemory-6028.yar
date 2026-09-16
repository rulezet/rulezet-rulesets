rule TTP_XOR_WriteProcessMemory_6028 {
  strings:
    $key_6028 = { 37 5a [2] 05 78 [2] 03 4d [2] 2d 4d [2] 12 51 }

  condition:
    any of them
}