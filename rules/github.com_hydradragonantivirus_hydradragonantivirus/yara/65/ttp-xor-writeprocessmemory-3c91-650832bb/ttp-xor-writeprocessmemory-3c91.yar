rule TTP_XOR_WriteProcessMemory_3c91 {
  strings:
    $key_3c91 = { 6b e3 [2] 59 c1 [2] 5f f4 [2] 71 f4 [2] 4e e8 }

  condition:
    any of them
}