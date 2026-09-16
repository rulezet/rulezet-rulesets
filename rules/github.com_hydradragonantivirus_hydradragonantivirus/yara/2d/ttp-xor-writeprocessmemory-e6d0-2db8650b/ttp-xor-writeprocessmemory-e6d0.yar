rule TTP_XOR_WriteProcessMemory_e6d0 {
  strings:
    $key_e6d0 = { b1 a2 [2] 83 80 [2] 85 b5 [2] ab b5 [2] 94 a9 }

  condition:
    any of them
}