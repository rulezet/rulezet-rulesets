rule TTP_XOR_WriteProcessMemory_fd3a {
  strings:
    $key_fd3a = { aa 48 [2] 98 6a [2] 9e 5f [2] b0 5f [2] 8f 43 }

  condition:
    any of them
}