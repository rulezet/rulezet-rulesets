rule TTP_XOR_WriteProcessMemory_fd90 {
  strings:
    $key_fd90 = { aa e2 [2] 98 c0 [2] 9e f5 [2] b0 f5 [2] 8f e9 }

  condition:
    any of them
}