rule TTP_XOR_WriteProcessMemory_fb5b {
  strings:
    $key_fb5b = { ac 29 [2] 9e 0b [2] 98 3e [2] b6 3e [2] 89 22 }

  condition:
    any of them
}