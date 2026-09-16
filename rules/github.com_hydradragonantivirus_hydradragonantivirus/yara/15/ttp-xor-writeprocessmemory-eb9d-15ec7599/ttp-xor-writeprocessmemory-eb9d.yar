rule TTP_XOR_WriteProcessMemory_eb9d {
  strings:
    $key_eb9d = { bc ef [2] 8e cd [2] 88 f8 [2] a6 f8 [2] 99 e4 }

  condition:
    any of them
}