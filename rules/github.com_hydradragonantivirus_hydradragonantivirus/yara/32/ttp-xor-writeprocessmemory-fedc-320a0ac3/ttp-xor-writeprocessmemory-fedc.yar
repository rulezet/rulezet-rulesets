rule TTP_XOR_WriteProcessMemory_fedc {
  strings:
    $key_fedc = { a9 ae [2] 9b 8c [2] 9d b9 [2] b3 b9 [2] 8c a5 }

  condition:
    any of them
}