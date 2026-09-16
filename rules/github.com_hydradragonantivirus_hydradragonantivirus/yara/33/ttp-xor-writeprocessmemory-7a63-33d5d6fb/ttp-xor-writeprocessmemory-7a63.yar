rule TTP_XOR_WriteProcessMemory_7a63 {
  strings:
    $key_7a63 = { 2d 11 [2] 1f 33 [2] 19 06 [2] 37 06 [2] 08 1a }

  condition:
    any of them
}