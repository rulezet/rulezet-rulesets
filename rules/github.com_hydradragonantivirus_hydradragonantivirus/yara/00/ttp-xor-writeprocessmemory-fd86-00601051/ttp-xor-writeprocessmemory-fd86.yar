rule TTP_XOR_WriteProcessMemory_fd86 {
  strings:
    $key_fd86 = { aa f4 [2] 98 d6 [2] 9e e3 [2] b0 e3 [2] 8f ff }

  condition:
    any of them
}