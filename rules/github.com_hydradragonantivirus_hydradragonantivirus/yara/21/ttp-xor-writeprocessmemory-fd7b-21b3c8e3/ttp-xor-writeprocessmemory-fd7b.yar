rule TTP_XOR_WriteProcessMemory_fd7b {
  strings:
    $key_fd7b = { aa 09 [2] 98 2b [2] 9e 1e [2] b0 1e [2] 8f 02 }

  condition:
    any of them
}