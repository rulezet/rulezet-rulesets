rule TTP_XOR_WriteProcessMemory_0091 {
  strings:
    $key_0091 = { 57 e3 [2] 65 c1 [2] 63 f4 [2] 4d f4 [2] 72 e8 }

  condition:
    any of them
}