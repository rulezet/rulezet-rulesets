rule TTP_XOR_WriteProcessMemory_fb2b {
  strings:
    $key_fb2b = { ac 59 [2] 9e 7b [2] 98 4e [2] b6 4e [2] 89 52 }

  condition:
    any of them
}