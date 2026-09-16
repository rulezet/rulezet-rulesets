rule TTP_XOR_WriteProcessMemory_fd9d {
  strings:
    $key_fd9d = { aa ef [2] 98 cd [2] 9e f8 [2] b0 f8 [2] 8f e4 }

  condition:
    any of them
}