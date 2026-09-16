rule TTP_XOR_WriteProcessMemory_f7cb {
  strings:
    $key_f7cb = { a0 b9 [2] 92 9b [2] 94 ae [2] ba ae [2] 85 b2 }

  condition:
    any of them
}