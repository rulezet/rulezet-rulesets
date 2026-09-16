rule TTP_XOR_WriteProcessMemory_fe6c {
  strings:
    $key_fe6c = { a9 1e [2] 9b 3c [2] 9d 09 [2] b3 09 [2] 8c 15 }

  condition:
    any of them
}