rule TTP_XOR_WriteProcessMemory_7291 {
  strings:
    $key_7291 = { 25 e3 [2] 17 c1 [2] 11 f4 [2] 3f f4 [2] 00 e8 }

  condition:
    any of them
}