rule TTP_XOR_WriteProcessMemory_4291 {
  strings:
    $key_4291 = { 15 e3 [2] 27 c1 [2] 21 f4 [2] 0f f4 [2] 30 e8 }

  condition:
    any of them
}