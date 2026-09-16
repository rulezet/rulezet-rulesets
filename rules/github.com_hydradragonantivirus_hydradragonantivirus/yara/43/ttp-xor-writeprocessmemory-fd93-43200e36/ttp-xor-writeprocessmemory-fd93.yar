rule TTP_XOR_WriteProcessMemory_fd93 {
  strings:
    $key_fd93 = { aa e1 [2] 98 c3 [2] 9e f6 [2] b0 f6 [2] 8f ea }

  condition:
    any of them
}