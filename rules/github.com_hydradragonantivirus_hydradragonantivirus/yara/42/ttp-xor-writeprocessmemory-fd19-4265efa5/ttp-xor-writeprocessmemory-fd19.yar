rule TTP_XOR_WriteProcessMemory_fd19 {
  strings:
    $key_fd19 = { aa 6b [2] 98 49 [2] 9e 7c [2] b0 7c [2] 8f 60 }

  condition:
    any of them
}