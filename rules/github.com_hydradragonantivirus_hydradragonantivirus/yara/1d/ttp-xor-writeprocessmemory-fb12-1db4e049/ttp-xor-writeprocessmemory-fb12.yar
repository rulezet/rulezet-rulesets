rule TTP_XOR_WriteProcessMemory_fb12 {
  strings:
    $key_fb12 = { ac 60 [2] 9e 42 [2] 98 77 [2] b6 77 [2] 89 6b }

  condition:
    any of them
}