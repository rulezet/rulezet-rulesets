rule TTP_XOR_WriteProcessMemory_4ee8 {
  strings:
    $key_4ee8 = { 19 9a [2] 2b b8 [2] 2d 8d [2] 03 8d [2] 3c 91 }

  condition:
    any of them
}