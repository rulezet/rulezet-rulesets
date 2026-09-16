rule TTP_XOR_WriteProcessMemory_fd8a {
  strings:
    $key_fd8a = { aa f8 [2] 98 da [2] 9e ef [2] b0 ef [2] 8f f3 }

  condition:
    any of them
}