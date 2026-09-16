rule TTP_XOR_WriteProcessMemory_2add {
  strings:
    $key_2add = { 7d af [2] 4f 8d [2] 49 b8 [2] 67 b8 [2] 58 a4 }

  condition:
    any of them
}