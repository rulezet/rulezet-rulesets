rule TTP_XOR_WriteProcessMemory_fd0b {
  strings:
    $key_fd0b = { aa 79 [2] 98 5b [2] 9e 6e [2] b0 6e [2] 8f 72 }

  condition:
    any of them
}