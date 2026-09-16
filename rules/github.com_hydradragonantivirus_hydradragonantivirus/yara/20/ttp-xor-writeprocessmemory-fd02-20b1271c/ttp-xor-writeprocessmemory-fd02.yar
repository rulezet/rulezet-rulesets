rule TTP_XOR_WriteProcessMemory_fd02 {
  strings:
    $key_fd02 = { aa 70 [2] 98 52 [2] 9e 67 [2] b0 67 [2] 8f 7b }

  condition:
    any of them
}