rule TTP_XOR_WriteProcessMemory_1719 {
  strings:
    $key_1719 = { 40 6b [2] 72 49 [2] 74 7c [2] 5a 7c [2] 65 60 }

  condition:
    any of them
}