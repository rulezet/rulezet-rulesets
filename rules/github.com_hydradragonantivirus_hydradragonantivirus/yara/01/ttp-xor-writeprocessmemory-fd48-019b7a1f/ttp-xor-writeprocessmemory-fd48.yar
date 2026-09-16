rule TTP_XOR_WriteProcessMemory_fd48 {
  strings:
    $key_fd48 = { aa 3a [2] 98 18 [2] 9e 2d [2] b0 2d [2] 8f 31 }

  condition:
    any of them
}