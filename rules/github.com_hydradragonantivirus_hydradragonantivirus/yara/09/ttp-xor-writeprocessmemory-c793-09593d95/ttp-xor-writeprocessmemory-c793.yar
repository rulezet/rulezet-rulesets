rule TTP_XOR_WriteProcessMemory_c793 {
  strings:
    $key_c793 = { 90 e1 [2] a2 c3 [2] a4 f6 [2] 8a f6 [2] b5 ea }

  condition:
    any of them
}