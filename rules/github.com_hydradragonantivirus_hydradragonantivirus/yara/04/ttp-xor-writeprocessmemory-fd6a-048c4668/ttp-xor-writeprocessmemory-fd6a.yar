rule TTP_XOR_WriteProcessMemory_fd6a {
  strings:
    $key_fd6a = { aa 18 [2] 98 3a [2] 9e 0f [2] b0 0f [2] 8f 13 }

  condition:
    any of them
}