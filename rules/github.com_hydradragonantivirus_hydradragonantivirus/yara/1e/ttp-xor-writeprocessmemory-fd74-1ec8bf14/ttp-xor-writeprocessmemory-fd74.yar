rule TTP_XOR_WriteProcessMemory_fd74 {
  strings:
    $key_fd74 = { aa 06 [2] 98 24 [2] 9e 11 [2] b0 11 [2] 8f 0d }

  condition:
    any of them
}