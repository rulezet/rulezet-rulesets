rule TTP_XOR_WriteProcessMemory_1add {
  strings:
    $key_1add = { 4d af [2] 7f 8d [2] 79 b8 [2] 57 b8 [2] 68 a4 }

  condition:
    any of them
}