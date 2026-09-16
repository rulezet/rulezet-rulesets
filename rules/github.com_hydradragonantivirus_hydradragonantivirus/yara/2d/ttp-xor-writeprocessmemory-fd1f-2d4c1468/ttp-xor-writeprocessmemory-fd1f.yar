rule TTP_XOR_WriteProcessMemory_fd1f {
  strings:
    $key_fd1f = { aa 6d [2] 98 4f [2] 9e 7a [2] b0 7a [2] 8f 66 }

  condition:
    any of them
}