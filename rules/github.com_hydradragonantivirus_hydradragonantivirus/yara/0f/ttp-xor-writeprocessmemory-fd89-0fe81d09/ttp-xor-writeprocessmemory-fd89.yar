rule TTP_XOR_WriteProcessMemory_fd89 {
  strings:
    $key_fd89 = { aa fb [2] 98 d9 [2] 9e ec [2] b0 ec [2] 8f f0 }

  condition:
    any of them
}