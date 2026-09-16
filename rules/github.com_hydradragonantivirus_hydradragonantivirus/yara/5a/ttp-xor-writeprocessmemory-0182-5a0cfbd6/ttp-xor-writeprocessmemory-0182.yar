rule TTP_XOR_WriteProcessMemory_0182 {
  strings:
    $key_0182 = { 56 f0 [2] 64 d2 [2] 62 e7 [2] 4c e7 [2] 73 fb }

  condition:
    any of them
}