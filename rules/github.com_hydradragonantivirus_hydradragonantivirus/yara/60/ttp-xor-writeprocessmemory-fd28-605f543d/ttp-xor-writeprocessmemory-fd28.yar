rule TTP_XOR_WriteProcessMemory_fd28 {
  strings:
    $key_fd28 = { aa 5a [2] 98 78 [2] 9e 4d [2] b0 4d [2] 8f 51 }

  condition:
    any of them
}