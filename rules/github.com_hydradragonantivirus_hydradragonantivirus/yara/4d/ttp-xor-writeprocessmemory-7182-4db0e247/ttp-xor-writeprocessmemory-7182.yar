rule TTP_XOR_WriteProcessMemory_7182 {
  strings:
    $key_7182 = { 26 f0 [2] 14 d2 [2] 12 e7 [2] 3c e7 [2] 03 fb }

  condition:
    any of them
}