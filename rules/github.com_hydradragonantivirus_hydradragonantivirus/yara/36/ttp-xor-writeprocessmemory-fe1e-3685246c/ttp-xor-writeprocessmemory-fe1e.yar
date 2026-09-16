rule TTP_XOR_WriteProcessMemory_fe1e {
  strings:
    $key_fe1e = { a9 6c [2] 9b 4e [2] 9d 7b [2] b3 7b [2] 8c 67 }

  condition:
    any of them
}