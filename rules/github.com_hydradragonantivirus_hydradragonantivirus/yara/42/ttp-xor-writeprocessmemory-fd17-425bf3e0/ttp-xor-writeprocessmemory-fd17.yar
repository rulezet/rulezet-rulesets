rule TTP_XOR_WriteProcessMemory_fd17 {
  strings:
    $key_fd17 = { aa 65 [2] 98 47 [2] 9e 72 [2] b0 72 [2] 8f 6e }

  condition:
    any of them
}