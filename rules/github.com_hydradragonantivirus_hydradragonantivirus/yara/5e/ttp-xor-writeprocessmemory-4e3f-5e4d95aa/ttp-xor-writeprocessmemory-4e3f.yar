rule TTP_XOR_WriteProcessMemory_4e3f {
  strings:
    $key_4e3f = { 19 4d [2] 2b 6f [2] 2d 5a [2] 03 5a [2] 3c 46 }

  condition:
    any of them
}