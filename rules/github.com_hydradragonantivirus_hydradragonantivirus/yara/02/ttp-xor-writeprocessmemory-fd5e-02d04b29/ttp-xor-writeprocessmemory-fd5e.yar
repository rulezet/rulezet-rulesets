rule TTP_XOR_WriteProcessMemory_fd5e {
  strings:
    $key_fd5e = { aa 2c [2] 98 0e [2] 9e 3b [2] b0 3b [2] 8f 27 }

  condition:
    any of them
}