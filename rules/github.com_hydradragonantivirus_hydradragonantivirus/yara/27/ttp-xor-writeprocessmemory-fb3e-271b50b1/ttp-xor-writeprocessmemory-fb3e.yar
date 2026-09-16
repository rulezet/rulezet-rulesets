rule TTP_XOR_WriteProcessMemory_fb3e {
  strings:
    $key_fb3e = { ac 4c [2] 9e 6e [2] 98 5b [2] b6 5b [2] 89 47 }

  condition:
    any of them
}