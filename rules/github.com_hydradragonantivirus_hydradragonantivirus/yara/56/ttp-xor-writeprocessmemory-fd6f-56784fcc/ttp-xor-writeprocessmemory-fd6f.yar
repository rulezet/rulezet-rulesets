rule TTP_XOR_WriteProcessMemory_fd6f {
  strings:
    $key_fd6f = { aa 1d [2] 98 3f [2] 9e 0a [2] b0 0a [2] 8f 16 }

  condition:
    any of them
}