rule TTP_XOR_WriteProcessMemory_fd21 {
  strings:
    $key_fd21 = { aa 53 [2] 98 71 [2] 9e 44 [2] b0 44 [2] 8f 58 }

  condition:
    any of them
}