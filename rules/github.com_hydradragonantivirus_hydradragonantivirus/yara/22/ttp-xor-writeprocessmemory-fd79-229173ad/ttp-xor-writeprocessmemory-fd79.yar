rule TTP_XOR_WriteProcessMemory_fd79 {
  strings:
    $key_fd79 = { aa 0b [2] 98 29 [2] 9e 1c [2] b0 1c [2] 8f 00 }

  condition:
    any of them
}