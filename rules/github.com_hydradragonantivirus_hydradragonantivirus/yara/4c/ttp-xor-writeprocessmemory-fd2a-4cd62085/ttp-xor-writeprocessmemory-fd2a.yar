rule TTP_XOR_WriteProcessMemory_fd2a {
  strings:
    $key_fd2a = { aa 58 [2] 98 7a [2] 9e 4f [2] b0 4f [2] 8f 53 }

  condition:
    any of them
}