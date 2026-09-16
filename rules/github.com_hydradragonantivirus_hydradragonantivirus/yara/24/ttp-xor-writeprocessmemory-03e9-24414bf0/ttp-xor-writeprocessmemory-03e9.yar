rule TTP_XOR_WriteProcessMemory_03e9 {
  strings:
    $key_03e9 = { 54 9b [2] 66 b9 [2] 60 8c [2] 4e 8c [2] 71 90 }

  condition:
    any of them
}