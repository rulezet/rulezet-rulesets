rule TTP_XOR_WriteProcessMemory_fd69 {
  strings:
    $key_fd69 = { aa 1b [2] 98 39 [2] 9e 0c [2] b0 0c [2] 8f 10 }

  condition:
    any of them
}