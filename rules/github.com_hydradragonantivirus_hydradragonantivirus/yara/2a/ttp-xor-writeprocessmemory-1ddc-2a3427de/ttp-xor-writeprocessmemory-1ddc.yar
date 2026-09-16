rule TTP_XOR_WriteProcessMemory_1ddc {
  strings:
    $key_1ddc = { 4a ae [2] 78 8c [2] 7e b9 [2] 50 b9 [2] 6f a5 }

  condition:
    any of them
}