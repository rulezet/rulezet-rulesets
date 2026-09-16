rule TTP_XOR_WriteProcessMemory_6b91 {
  strings:
    $key_6b91 = { 3c e3 [2] 0e c1 [2] 08 f4 [2] 26 f4 [2] 19 e8 }

  condition:
    any of them
}