rule TTP_XOR_WriteProcessMemory_fd80 {
  strings:
    $key_fd80 = { aa f2 [2] 98 d0 [2] 9e e5 [2] b0 e5 [2] 8f f9 }

  condition:
    any of them
}