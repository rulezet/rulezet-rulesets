rule TTP_XOR_WriteProcessMemory_fd91 {
  strings:
    $key_fd91 = { aa e3 [2] 98 c1 [2] 9e f4 [2] b0 f4 [2] 8f e8 }

  condition:
    any of them
}