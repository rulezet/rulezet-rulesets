rule TTP_XOR_WriteProcessMemory_fd64 {
  strings:
    $key_fd64 = { aa 16 [2] 98 34 [2] 9e 01 [2] b0 01 [2] 8f 1d }

  condition:
    any of them
}