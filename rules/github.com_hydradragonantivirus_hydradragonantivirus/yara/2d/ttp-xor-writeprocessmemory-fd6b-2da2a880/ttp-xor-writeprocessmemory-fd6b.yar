rule TTP_XOR_WriteProcessMemory_fd6b {
  strings:
    $key_fd6b = { aa 19 [2] 98 3b [2] 9e 0e [2] b0 0e [2] 8f 12 }

  condition:
    any of them
}