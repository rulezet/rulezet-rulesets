rule TTP_XOR_WriteProcessMemory_78ee {
  strings:
    $key_78ee = { 2f 9c [2] 1d be [2] 1b 8b [2] 35 8b [2] 0a 97 }

  condition:
    any of them
}