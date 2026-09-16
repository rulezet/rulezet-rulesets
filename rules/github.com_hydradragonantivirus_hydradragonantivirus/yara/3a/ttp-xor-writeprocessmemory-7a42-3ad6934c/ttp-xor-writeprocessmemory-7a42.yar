rule TTP_XOR_WriteProcessMemory_7a42 {
  strings:
    $key_7a42 = { 2d 30 [2] 1f 12 [2] 19 27 [2] 37 27 [2] 08 3b }

  condition:
    any of them
}