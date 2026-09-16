rule TTP_XOR_WriteProcessMemory_fd8d {
  strings:
    $key_fd8d = { aa ff [2] 98 dd [2] 9e e8 [2] b0 e8 [2] 8f f4 }

  condition:
    any of them
}