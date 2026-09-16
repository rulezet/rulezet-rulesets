rule TTP_XOR_WriteProcessMemory_6add {
  strings:
    $key_6add = { 3d af [2] 0f 8d [2] 09 b8 [2] 27 b8 [2] 18 a4 }

  condition:
    any of them
}