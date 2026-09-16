rule TTP_XOR_WriteProcessMemory_3091 {
  strings:
    $key_3091 = { 67 e3 [2] 55 c1 [2] 53 f4 [2] 7d f4 [2] 42 e8 }

  condition:
    any of them
}