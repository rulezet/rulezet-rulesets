rule TTP_XOR_WriteProcessMemory_fd76 {
  strings:
    $key_fd76 = { aa 04 [2] 98 26 [2] 9e 13 [2] b0 13 [2] 8f 0f }

  condition:
    any of them
}