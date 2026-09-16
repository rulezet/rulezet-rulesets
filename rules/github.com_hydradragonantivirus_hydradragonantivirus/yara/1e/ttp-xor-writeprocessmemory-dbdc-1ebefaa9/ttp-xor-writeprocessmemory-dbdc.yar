rule TTP_XOR_WriteProcessMemory_dbdc {
  strings:
    $key_dbdc = { 8c ae [2] be 8c [2] b8 b9 [2] 96 b9 [2] a9 a5 }

  condition:
    any of them
}