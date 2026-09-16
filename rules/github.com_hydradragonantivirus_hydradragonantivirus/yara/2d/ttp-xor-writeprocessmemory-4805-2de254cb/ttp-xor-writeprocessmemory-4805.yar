rule TTP_XOR_WriteProcessMemory_4805 {
  strings:
    $key_4805 = { 1f 77 [2] 2d 55 [2] 2b 60 [2] 05 60 [2] 3a 7c }

  condition:
    any of them
}