rule TTP_XOR_WriteProcessMemory_5091 {
  strings:
    $key_5091 = { 07 e3 [2] 35 c1 [2] 33 f4 [2] 1d f4 [2] 22 e8 }

  condition:
    any of them
}