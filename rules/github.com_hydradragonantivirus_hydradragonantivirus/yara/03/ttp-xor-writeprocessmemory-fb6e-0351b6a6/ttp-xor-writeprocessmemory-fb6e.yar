rule TTP_XOR_WriteProcessMemory_fb6e {
  strings:
    $key_fb6e = { ac 1c [2] 9e 3e [2] 98 0b [2] b6 0b [2] 89 17 }

  condition:
    any of them
}