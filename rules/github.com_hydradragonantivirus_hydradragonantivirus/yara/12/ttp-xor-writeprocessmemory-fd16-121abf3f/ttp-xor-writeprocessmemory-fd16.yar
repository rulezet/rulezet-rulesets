rule TTP_XOR_WriteProcessMemory_fd16 {
  strings:
    $key_fd16 = { aa 64 [2] 98 46 [2] 9e 73 [2] b0 73 [2] 8f 6f }

  condition:
    any of them
}