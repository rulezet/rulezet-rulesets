rule TTP_XOR_WriteProcessMemory_6bdc {
  strings:
    $key_6bdc = { 3c ae [2] 0e 8c [2] 08 b9 [2] 26 b9 [2] 19 a5 }

  condition:
    any of them
}