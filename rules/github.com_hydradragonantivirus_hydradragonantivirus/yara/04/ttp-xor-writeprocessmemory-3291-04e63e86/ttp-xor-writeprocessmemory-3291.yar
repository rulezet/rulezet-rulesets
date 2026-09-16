rule TTP_XOR_WriteProcessMemory_3291 {
  strings:
    $key_3291 = { 65 e3 [2] 57 c1 [2] 51 f4 [2] 7f f4 [2] 40 e8 }

  condition:
    any of them
}