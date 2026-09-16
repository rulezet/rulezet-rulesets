rule TTP_XOR_WriteProcessMemory_fd95 {
  strings:
    $key_fd95 = { aa e7 [2] 98 c5 [2] 9e f0 [2] b0 f0 [2] 8f ec }

  condition:
    any of them
}