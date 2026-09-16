rule TTP_XOR_WriteProcessMemory_fb00 {
  strings:
    $key_fb00 = { ac 72 [2] 9e 50 [2] 98 65 [2] b6 65 [2] 89 79 }

  condition:
    any of them
}