rule TTP_XOR_WriteProcessMemory_e091 {
  strings:
    $key_e091 = { b7 e3 [2] 85 c1 [2] 83 f4 [2] ad f4 [2] 92 e8 }

  condition:
    any of them
}