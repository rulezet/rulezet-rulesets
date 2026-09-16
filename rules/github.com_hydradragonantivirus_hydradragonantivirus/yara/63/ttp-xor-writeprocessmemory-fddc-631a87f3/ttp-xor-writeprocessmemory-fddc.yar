rule TTP_XOR_WriteProcessMemory_fddc {
  strings:
    $key_fddc = { aa ae [2] 98 8c [2] 9e b9 [2] b0 b9 [2] 8f a5 }

  condition:
    any of them
}