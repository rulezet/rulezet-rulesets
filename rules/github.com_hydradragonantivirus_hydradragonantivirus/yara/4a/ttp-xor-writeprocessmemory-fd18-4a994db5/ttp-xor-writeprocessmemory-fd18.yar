rule TTP_XOR_WriteProcessMemory_fd18 {
  strings:
    $key_fd18 = { aa 6a [2] 98 48 [2] 9e 7d [2] b0 7d [2] 8f 61 }

  condition:
    any of them
}