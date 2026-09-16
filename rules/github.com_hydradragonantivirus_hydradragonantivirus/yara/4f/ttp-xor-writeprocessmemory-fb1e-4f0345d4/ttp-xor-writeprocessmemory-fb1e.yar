rule TTP_XOR_WriteProcessMemory_fb1e {
  strings:
    $key_fb1e = { ac 6c [2] 9e 4e [2] 98 7b [2] b6 7b [2] 89 67 }

  condition:
    any of them
}