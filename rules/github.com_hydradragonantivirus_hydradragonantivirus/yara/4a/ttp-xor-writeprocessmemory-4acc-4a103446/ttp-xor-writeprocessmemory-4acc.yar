rule TTP_XOR_WriteProcessMemory_4acc {
  strings:
    $key_4acc = { 1d be [2] 2f 9c [2] 29 a9 [2] 07 a9 [2] 38 b5 }

  condition:
    any of them
}