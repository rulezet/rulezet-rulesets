rule TTP_XOR_WriteProcessMemory_fd81 {
  strings:
    $key_fd81 = { aa f3 [2] 98 d1 [2] 9e e4 [2] b0 e4 [2] 8f f8 }

  condition:
    any of them
}