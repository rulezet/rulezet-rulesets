rule TTP_XOR_WriteProcessMemory_fd34 {
  strings:
    $key_fd34 = { aa 46 [2] 98 64 [2] 9e 51 [2] b0 51 [2] 8f 4d }

  condition:
    any of them
}