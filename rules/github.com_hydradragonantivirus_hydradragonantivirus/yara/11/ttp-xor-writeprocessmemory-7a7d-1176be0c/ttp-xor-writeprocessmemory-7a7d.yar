rule TTP_XOR_WriteProcessMemory_7a7d {
  strings:
    $key_7a7d = { 2d 0f [2] 1f 2d [2] 19 18 [2] 37 18 [2] 08 04 }

  condition:
    any of them
}