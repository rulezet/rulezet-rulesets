rule TTP_XOR_WriteProcessMemory_fb3c {
  strings:
    $key_fb3c = { ac 4e [2] 9e 6c [2] 98 59 [2] b6 59 [2] 89 45 }

  condition:
    any of them
}