rule TTP_XOR_WriteProcessMemory_7a60 {
  strings:
    $key_7a60 = { 2d 12 [2] 1f 30 [2] 19 05 [2] 37 05 [2] 08 19 }

  condition:
    any of them
}