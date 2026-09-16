rule TTP_XOR_WriteProcessMemory_7a0d {
  strings:
    $key_7a0d = { 2d 7f [2] 1f 5d [2] 19 68 [2] 37 68 [2] 08 74 }

  condition:
    any of them
}