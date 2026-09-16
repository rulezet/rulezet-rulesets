rule TTP_XOR_WriteProcessMemory_fb79 {
  strings:
    $key_fb79 = { ac 0b [2] 9e 29 [2] 98 1c [2] b6 1c [2] 89 00 }

  condition:
    any of them
}