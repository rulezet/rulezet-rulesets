rule TTP_XOR_WriteProcessMemory_fb41 {
  strings:
    $key_fb41 = { ac 33 [2] 9e 11 [2] 98 24 [2] b6 24 [2] 89 38 }

  condition:
    any of them
}