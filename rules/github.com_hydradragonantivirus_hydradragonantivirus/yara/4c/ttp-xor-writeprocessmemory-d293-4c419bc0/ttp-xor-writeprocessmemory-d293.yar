rule TTP_XOR_WriteProcessMemory_d293 {
  strings:
    $key_d293 = { 85 e1 [2] b7 c3 [2] b1 f6 [2] 9f f6 [2] a0 ea }

  condition:
    any of them
}