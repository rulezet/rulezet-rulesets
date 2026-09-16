rule TTP_XOR_WriteProcessMemory_fd87 {
  strings:
    $key_fd87 = { aa f5 [2] 98 d7 [2] 9e e2 [2] b0 e2 [2] 8f fe }

  condition:
    any of them
}