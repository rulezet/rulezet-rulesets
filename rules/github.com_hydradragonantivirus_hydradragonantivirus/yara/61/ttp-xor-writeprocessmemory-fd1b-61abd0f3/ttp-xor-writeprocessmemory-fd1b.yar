rule TTP_XOR_WriteProcessMemory_fd1b {
  strings:
    $key_fd1b = { aa 69 [2] 98 4b [2] 9e 7e [2] b0 7e [2] 8f 62 }

  condition:
    any of them
}