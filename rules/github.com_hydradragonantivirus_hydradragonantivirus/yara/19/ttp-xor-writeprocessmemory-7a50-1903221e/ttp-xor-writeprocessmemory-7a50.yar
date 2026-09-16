rule TTP_XOR_WriteProcessMemory_7a50 {
  strings:
    $key_7a50 = { 2d 22 [2] 1f 00 [2] 19 35 [2] 37 35 [2] 08 29 }

  condition:
    any of them
}