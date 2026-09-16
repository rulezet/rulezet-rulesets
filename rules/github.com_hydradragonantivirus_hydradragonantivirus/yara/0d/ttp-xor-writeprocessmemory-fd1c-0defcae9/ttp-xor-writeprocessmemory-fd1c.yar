rule TTP_XOR_WriteProcessMemory_fd1c {
  strings:
    $key_fd1c = { aa 6e [2] 98 4c [2] 9e 79 [2] b0 79 [2] 8f 65 }

  condition:
    any of them
}