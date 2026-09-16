rule TTP_XOR_WriteProcessMemory_fe3b {
  strings:
    $key_fe3b = { a9 49 [2] 9b 6b [2] 9d 5e [2] b3 5e [2] 8c 42 }

  condition:
    any of them
}