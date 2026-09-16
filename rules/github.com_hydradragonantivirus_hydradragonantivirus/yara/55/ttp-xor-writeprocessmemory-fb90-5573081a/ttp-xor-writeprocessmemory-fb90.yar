rule TTP_XOR_WriteProcessMemory_fb90 {
  strings:
    $key_fb90 = { ac e2 [2] 9e c0 [2] 98 f5 [2] b6 f5 [2] 89 e9 }

  condition:
    any of them
}