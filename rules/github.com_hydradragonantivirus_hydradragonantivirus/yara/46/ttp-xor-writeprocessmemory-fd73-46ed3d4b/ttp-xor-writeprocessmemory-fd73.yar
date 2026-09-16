rule TTP_XOR_WriteProcessMemory_fd73 {
  strings:
    $key_fd73 = { aa 01 [2] 98 23 [2] 9e 16 [2] b0 16 [2] 8f 0a }

  condition:
    any of them
}