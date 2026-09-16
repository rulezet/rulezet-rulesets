rule TTP_XOR_WriteProcessMemory_fd7f {
  strings:
    $key_fd7f = { aa 0d [2] 98 2f [2] 9e 1a [2] b0 1a [2] 8f 06 }

  condition:
    any of them
}