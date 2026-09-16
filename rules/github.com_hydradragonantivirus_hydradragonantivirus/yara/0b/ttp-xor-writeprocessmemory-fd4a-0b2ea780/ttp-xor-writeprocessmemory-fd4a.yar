rule TTP_XOR_WriteProcessMemory_fd4a {
  strings:
    $key_fd4a = { aa 38 [2] 98 1a [2] 9e 2f [2] b0 2f [2] 8f 33 }

  condition:
    any of them
}