rule TTP_XOR_WriteProcessMemory_fd5b {
  strings:
    $key_fd5b = { aa 29 [2] 98 0b [2] 9e 3e [2] b0 3e [2] 8f 22 }

  condition:
    any of them
}