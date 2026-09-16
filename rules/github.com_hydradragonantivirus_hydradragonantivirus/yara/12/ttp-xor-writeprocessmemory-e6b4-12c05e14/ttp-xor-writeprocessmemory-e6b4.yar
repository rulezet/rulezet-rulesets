rule TTP_XOR_WriteProcessMemory_e6b4 {
  strings:
    $key_e6b4 = { b1 c6 [2] 83 e4 [2] 85 d1 [2] ab d1 [2] 94 cd }

  condition:
    any of them
}