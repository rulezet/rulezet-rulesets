rule TTP_XOR_WriteProcessMemory_36d0 {
  strings:
    $key_36d0 = { 61 a2 [2] 53 80 [2] 55 b5 [2] 7b b5 [2] 44 a9 }

  condition:
    any of them
}