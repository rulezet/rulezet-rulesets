rule TTP_XOR_WriteProcessMemory_7ddc {
  strings:
    $key_7ddc = { 2a ae [2] 18 8c [2] 1e b9 [2] 30 b9 [2] 0f a5 }

  condition:
    any of them
}