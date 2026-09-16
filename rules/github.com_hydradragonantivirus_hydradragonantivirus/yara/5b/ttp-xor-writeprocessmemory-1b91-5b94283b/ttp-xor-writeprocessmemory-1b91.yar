rule TTP_XOR_WriteProcessMemory_1b91 {
  strings:
    $key_1b91 = { 4c e3 [2] 7e c1 [2] 78 f4 [2] 56 f4 [2] 69 e8 }

  condition:
    any of them
}