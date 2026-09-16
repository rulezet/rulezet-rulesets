rule TTP_XOR_WriteProcessMemory_fd1e {
  strings:
    $key_fd1e = { aa 6c [2] 98 4e [2] 9e 7b [2] b0 7b [2] 8f 67 }

  condition:
    any of them
}