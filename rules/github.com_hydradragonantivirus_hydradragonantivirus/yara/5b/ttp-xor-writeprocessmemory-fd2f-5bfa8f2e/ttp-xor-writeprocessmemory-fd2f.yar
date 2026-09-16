rule TTP_XOR_WriteProcessMemory_fd2f {
  strings:
    $key_fd2f = { aa 5d [2] 98 7f [2] 9e 4a [2] b0 4a [2] 8f 56 }

  condition:
    any of them
}