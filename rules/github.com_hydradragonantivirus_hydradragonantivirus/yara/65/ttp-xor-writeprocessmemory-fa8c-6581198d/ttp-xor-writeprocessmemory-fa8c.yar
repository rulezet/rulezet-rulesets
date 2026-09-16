rule TTP_XOR_WriteProcessMemory_fa8c {
  strings:
    $key_fa8c = { ad fe [2] 9f dc [2] 99 e9 [2] b7 e9 [2] 88 f5 }

  condition:
    any of them
}