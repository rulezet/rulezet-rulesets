rule TTP_XOR_WriteProcessMemory_e6b9 {
  strings:
    $key_e6b9 = { b1 cb [2] 83 e9 [2] 85 dc [2] ab dc [2] 94 c0 }

  condition:
    any of them
}