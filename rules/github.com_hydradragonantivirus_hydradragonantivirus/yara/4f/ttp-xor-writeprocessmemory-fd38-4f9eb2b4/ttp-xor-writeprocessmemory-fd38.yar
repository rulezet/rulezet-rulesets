rule TTP_XOR_WriteProcessMemory_fd38 {
  strings:
    $key_fd38 = { aa 4a [2] 98 68 [2] 9e 5d [2] b0 5d [2] 8f 41 }

  condition:
    any of them
}