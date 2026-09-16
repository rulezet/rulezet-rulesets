rule TTP_XOR_WriteProcessMemory_6acc {
  strings:
    $key_6acc = { 3d be [2] 0f 9c [2] 09 a9 [2] 27 a9 [2] 18 b5 }

  condition:
    any of them
}