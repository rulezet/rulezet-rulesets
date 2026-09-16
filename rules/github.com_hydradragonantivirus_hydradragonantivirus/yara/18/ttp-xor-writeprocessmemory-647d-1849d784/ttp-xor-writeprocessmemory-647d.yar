rule TTP_XOR_WriteProcessMemory_647d {
  strings:
    $key_647d = { 33 0f [2] 01 2d [2] 07 18 [2] 29 18 [2] 16 04 }

  condition:
    any of them
}