rule TTP_XOR_WriteProcessMemory_7a12 {
  strings:
    $key_7a12 = { 2d 60 [2] 1f 42 [2] 19 77 [2] 37 77 [2] 08 6b }

  condition:
    any of them
}