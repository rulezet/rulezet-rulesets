rule TTP_XOR_WriteProcessMemory_5a7d {
  strings:
    $key_5a7d = { 0d 0f [2] 3f 2d [2] 39 18 [2] 17 18 [2] 28 04 }

  condition:
    any of them
}