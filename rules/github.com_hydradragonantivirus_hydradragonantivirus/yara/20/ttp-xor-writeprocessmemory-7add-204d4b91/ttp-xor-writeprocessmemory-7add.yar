rule TTP_XOR_WriteProcessMemory_7add {
  strings:
    $key_7add = { 2d af [2] 1f 8d [2] 19 b8 [2] 37 b8 [2] 08 a4 }

  condition:
    any of them
}