rule TTP_XOR_WriteProcessMemory_2b92 {
  strings:
    $key_2b92 = { 7c e0 [2] 4e c2 [2] 48 f7 [2] 66 f7 [2] 59 eb }

  condition:
    any of them
}