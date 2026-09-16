rule TTP_XOR_WriteProcessMemory_3bdc {
  strings:
    $key_3bdc = { 6c ae [2] 5e 8c [2] 58 b9 [2] 76 b9 [2] 49 a5 }

  condition:
    any of them
}