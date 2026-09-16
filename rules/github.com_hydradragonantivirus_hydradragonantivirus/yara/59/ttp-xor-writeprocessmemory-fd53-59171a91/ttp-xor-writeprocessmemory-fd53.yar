rule TTP_XOR_WriteProcessMemory_fd53 {
  strings:
    $key_fd53 = { aa 21 [2] 98 03 [2] 9e 36 [2] b0 36 [2] 8f 2a }

  condition:
    any of them
}