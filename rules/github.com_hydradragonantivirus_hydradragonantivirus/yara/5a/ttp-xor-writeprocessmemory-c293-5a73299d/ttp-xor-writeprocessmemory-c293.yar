rule TTP_XOR_WriteProcessMemory_c293 {
  strings:
    $key_c293 = { 95 e1 [2] a7 c3 [2] a1 f6 [2] 8f f6 [2] b0 ea }

  condition:
    any of them
}