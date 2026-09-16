rule TTP_XOR_WriteProcessMemory_fe0e {
  strings:
    $key_fe0e = { a9 7c [2] 9b 5e [2] 9d 6b [2] b3 6b [2] 8c 77 }

  condition:
    any of them
}