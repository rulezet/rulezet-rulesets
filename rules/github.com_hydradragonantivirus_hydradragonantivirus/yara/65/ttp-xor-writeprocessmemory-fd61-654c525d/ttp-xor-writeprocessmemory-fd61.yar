rule TTP_XOR_WriteProcessMemory_fd61 {
  strings:
    $key_fd61 = { aa 13 [2] 98 31 [2] 9e 04 [2] b0 04 [2] 8f 18 }

  condition:
    any of them
}