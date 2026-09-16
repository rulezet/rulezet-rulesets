rule TTP_XOR_WriteProcessMemory_2bd0 {
  strings:
    $key_2bd0 = { 7c a2 [2] 4e 80 [2] 48 b5 [2] 66 b5 [2] 59 a9 }

  condition:
    any of them
}