rule TTP_XOR_WriteProcessMemory_3acc {
  strings:
    $key_3acc = { 6d be [2] 5f 9c [2] 59 a9 [2] 77 a9 [2] 48 b5 }

  condition:
    any of them
}