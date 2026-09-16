rule TTP_XOR_WriteProcessMemory_fb91 {
  strings:
    $key_fb91 = { ac e3 [2] 9e c1 [2] 98 f4 [2] b6 f4 [2] 89 e8 }

  condition:
    any of them
}