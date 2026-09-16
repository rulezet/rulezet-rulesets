rule TTP_XOR_WriteProcessMemory_7a22 {
  strings:
    $key_7a22 = { 2d 50 [2] 1f 72 [2] 19 47 [2] 37 47 [2] 08 5b }

  condition:
    any of them
}