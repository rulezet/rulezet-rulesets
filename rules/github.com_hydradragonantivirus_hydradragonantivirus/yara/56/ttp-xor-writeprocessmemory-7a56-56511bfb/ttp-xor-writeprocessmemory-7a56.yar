rule TTP_XOR_WriteProcessMemory_7a56 {
  strings:
    $key_7a56 = { 2d 24 [2] 1f 06 [2] 19 33 [2] 37 33 [2] 08 2f }

  condition:
    any of them
}