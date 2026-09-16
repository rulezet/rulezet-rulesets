rule TTP_XOR_WriteProcessMemory_fd7e {
  strings:
    $key_fd7e = { aa 0c [2] 98 2e [2] 9e 1b [2] b0 1b [2] 8f 07 }

  condition:
    any of them
}