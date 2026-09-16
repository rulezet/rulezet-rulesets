rule TTP_XOR_WriteProcessMemory_1e91 {
  strings:
    $key_1e91 = { 49 e3 [2] 7b c1 [2] 7d f4 [2] 53 f4 [2] 6c e8 }

  condition:
    any of them
}