rule TTP_XOR_WriteProcessMemory_2519 {
  strings:
    $key_2519 = { 72 6b [2] 40 49 [2] 46 7c [2] 68 7c [2] 57 60 }

  condition:
    any of them
}