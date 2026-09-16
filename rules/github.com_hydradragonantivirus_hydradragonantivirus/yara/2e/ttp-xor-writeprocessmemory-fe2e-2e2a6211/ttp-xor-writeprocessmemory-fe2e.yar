rule TTP_XOR_WriteProcessMemory_fe2e {
  strings:
    $key_fe2e = { a9 5c [2] 9b 7e [2] 9d 4b [2] b3 4b [2] 8c 57 }

  condition:
    any of them
}