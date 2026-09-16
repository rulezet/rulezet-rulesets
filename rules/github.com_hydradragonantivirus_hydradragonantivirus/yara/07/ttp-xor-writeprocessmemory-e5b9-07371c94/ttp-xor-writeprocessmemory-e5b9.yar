rule TTP_XOR_WriteProcessMemory_e5b9 {
  strings:
    $key_e5b9 = { b2 cb [2] 80 e9 [2] 86 dc [2] a8 dc [2] 97 c0 }

  condition:
    any of them
}