rule TTP_XOR_WriteProcessMemory_fb26 {
  strings:
    $key_fb26 = { ac 54 [2] 9e 76 [2] 98 43 [2] b6 43 [2] 89 5f }

  condition:
    any of them
}