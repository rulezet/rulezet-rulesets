rule TTP_XOR_WriteProcessMemory_c193 {
  strings:
    $key_c193 = { 96 e1 [2] a4 c3 [2] a2 f6 [2] 8c f6 [2] b3 ea }

  condition:
    any of them
}