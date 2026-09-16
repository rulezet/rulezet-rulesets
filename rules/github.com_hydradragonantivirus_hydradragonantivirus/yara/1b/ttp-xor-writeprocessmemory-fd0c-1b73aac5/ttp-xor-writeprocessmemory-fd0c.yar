rule TTP_XOR_WriteProcessMemory_fd0c {
  strings:
    $key_fd0c = { aa 7e [2] 98 5c [2] 9e 69 [2] b0 69 [2] 8f 75 }

  condition:
    any of them
}