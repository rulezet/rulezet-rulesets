rule TTP_XOR_WriteProcessMemory_28ee {
  strings:
    $key_28ee = { 7f 9c [2] 4d be [2] 4b 8b [2] 65 8b [2] 5a 97 }

  condition:
    any of them
}