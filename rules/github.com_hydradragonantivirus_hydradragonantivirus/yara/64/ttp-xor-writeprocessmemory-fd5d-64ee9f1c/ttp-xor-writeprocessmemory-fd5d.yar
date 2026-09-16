rule TTP_XOR_WriteProcessMemory_fd5d {
  strings:
    $key_fd5d = { aa 2f [2] 98 0d [2] 9e 38 [2] b0 38 [2] 8f 24 }

  condition:
    any of them
}