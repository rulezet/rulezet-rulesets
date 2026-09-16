rule TTP_XOR_WriteProcessMemory_fd60 {
  strings:
    $key_fd60 = { aa 12 [2] 98 30 [2] 9e 05 [2] b0 05 [2] 8f 19 }

  condition:
    any of them
}