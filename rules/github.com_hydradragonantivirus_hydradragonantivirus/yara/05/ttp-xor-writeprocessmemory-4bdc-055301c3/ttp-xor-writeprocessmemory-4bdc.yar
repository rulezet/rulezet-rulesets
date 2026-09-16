rule TTP_XOR_WriteProcessMemory_4bdc {
  strings:
    $key_4bdc = { 1c ae [2] 2e 8c [2] 28 b9 [2] 06 b9 [2] 39 a5 }

  condition:
    any of them
}