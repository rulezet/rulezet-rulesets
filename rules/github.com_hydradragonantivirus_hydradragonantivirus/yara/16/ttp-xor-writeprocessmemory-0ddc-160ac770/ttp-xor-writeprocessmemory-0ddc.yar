rule TTP_XOR_WriteProcessMemory_0ddc {
  strings:
    $key_0ddc = { 5a ae [2] 68 8c [2] 6e b9 [2] 40 b9 [2] 7f a5 }

  condition:
    any of them
}