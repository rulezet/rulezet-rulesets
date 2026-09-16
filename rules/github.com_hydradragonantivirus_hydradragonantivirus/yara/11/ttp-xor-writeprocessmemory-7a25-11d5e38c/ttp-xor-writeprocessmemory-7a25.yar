rule TTP_XOR_WriteProcessMemory_7a25 {
  strings:
    $key_7a25 = { 2d 57 [2] 1f 75 [2] 19 40 [2] 37 40 [2] 08 5c }

  condition:
    any of them
}