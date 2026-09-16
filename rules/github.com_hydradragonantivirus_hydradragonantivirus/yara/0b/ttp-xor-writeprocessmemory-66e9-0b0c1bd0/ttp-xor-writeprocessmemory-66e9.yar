rule TTP_XOR_WriteProcessMemory_66e9 {
  strings:
    $key_66e9 = { 31 9b [2] 03 b9 [2] 05 8c [2] 2b 8c [2] 14 90 }

  condition:
    any of them
}