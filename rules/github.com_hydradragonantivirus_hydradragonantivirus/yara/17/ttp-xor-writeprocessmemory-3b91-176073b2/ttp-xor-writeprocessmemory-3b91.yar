rule TTP_XOR_WriteProcessMemory_3b91 {
  strings:
    $key_3b91 = { 6c e3 [2] 5e c1 [2] 58 f4 [2] 76 f4 [2] 49 e8 }

  condition:
    any of them
}