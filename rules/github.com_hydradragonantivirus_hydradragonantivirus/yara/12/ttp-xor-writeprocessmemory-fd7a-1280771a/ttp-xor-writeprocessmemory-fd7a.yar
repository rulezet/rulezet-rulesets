rule TTP_XOR_WriteProcessMemory_fd7a {
  strings:
    $key_fd7a = { aa 08 [2] 98 2a [2] 9e 1f [2] b0 1f [2] 8f 03 }

  condition:
    any of them
}