rule TTP_XOR_WriteProcessMemory_fb6b {
  strings:
    $key_fb6b = { ac 19 [2] 9e 3b [2] 98 0e [2] b6 0e [2] 89 12 }

  condition:
    any of them
}