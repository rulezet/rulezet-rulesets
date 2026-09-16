rule TTP_XOR_WriteProcessMemory_fd14 {
  strings:
    $key_fd14 = { aa 66 [2] 98 44 [2] 9e 71 [2] b0 71 [2] 8f 6d }

  condition:
    any of them
}