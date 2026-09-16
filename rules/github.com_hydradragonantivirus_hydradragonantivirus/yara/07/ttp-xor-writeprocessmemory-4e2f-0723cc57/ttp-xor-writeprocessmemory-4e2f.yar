rule TTP_XOR_WriteProcessMemory_4e2f {
  strings:
    $key_4e2f = { 19 5d [2] 2b 7f [2] 2d 4a [2] 03 4a [2] 3c 56 }

  condition:
    any of them
}