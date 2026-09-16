rule TTP_XOR_WriteProcessMemory_0291 {
  strings:
    $key_0291 = { 55 e3 [2] 67 c1 [2] 61 f4 [2] 4f f4 [2] 70 e8 }

  condition:
    any of them
}