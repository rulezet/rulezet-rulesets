rule TTP_XOR_WriteProcessMemory_4182 {
  strings:
    $key_4182 = { 16 f0 [2] 24 d2 [2] 22 e7 [2] 0c e7 [2] 33 fb }

  condition:
    any of them
}