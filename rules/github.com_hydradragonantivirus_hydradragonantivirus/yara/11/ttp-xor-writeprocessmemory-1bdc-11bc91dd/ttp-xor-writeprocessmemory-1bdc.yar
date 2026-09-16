rule TTP_XOR_WriteProcessMemory_1bdc {
  strings:
    $key_1bdc = { 4c ae [2] 7e 8c [2] 78 b9 [2] 56 b9 [2] 69 a5 }

  condition:
    any of them
}