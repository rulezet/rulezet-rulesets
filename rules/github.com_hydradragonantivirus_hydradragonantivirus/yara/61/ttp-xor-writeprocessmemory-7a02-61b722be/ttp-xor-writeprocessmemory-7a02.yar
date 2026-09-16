rule TTP_XOR_WriteProcessMemory_7a02 {
  strings:
    $key_7a02 = { 2d 70 [2] 1f 52 [2] 19 67 [2] 37 67 [2] 08 7b }

  condition:
    any of them
}