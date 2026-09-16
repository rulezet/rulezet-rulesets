rule TTP_XOR_WriteProcessMemory_fb46 {
  strings:
    $key_fb46 = { ac 34 [2] 9e 16 [2] 98 23 [2] b6 23 [2] 89 3f }

  condition:
    any of them
}