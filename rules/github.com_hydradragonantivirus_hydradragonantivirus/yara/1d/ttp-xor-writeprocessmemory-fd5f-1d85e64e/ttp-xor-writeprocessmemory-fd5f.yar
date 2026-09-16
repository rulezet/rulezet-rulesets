rule TTP_XOR_WriteProcessMemory_fd5f {
  strings:
    $key_fd5f = { aa 2d [2] 98 0f [2] 9e 3a [2] b0 3a [2] 8f 26 }

  condition:
    any of them
}