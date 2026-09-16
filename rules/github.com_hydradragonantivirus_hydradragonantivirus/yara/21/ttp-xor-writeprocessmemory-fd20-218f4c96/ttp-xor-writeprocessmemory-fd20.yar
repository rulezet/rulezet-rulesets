rule TTP_XOR_WriteProcessMemory_fd20 {
  strings:
    $key_fd20 = { aa 52 [2] 98 70 [2] 9e 45 [2] b0 45 [2] 8f 59 }

  condition:
    any of them
}