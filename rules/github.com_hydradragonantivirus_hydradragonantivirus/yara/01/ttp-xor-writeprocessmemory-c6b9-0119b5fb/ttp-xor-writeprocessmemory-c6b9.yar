rule TTP_XOR_WriteProcessMemory_c6b9 {
  strings:
    $key_c6b9 = { 91 cb [2] a3 e9 [2] a5 dc [2] 8b dc [2] b4 c0 }

  condition:
    any of them
}