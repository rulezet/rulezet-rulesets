rule TTP_XOR_WriteProcessMemory_fd35 {
  strings:
    $key_fd35 = { aa 47 [2] 98 65 [2] 9e 50 [2] b0 50 [2] 8f 4c }

  condition:
    any of them
}