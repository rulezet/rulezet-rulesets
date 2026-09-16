rule TTP_XOR_WriteProcessMemory_fd9b {
  strings:
    $key_fd9b = { aa e9 [2] 98 cb [2] 9e fe [2] b0 fe [2] 8f e2 }

  condition:
    any of them
}