rule TTP_XOR_WriteProcessMemory_2b91 {
  strings:
    $key_2b91 = { 7c e3 [2] 4e c1 [2] 48 f4 [2] 66 f4 [2] 59 e8 }

  condition:
    any of them
}