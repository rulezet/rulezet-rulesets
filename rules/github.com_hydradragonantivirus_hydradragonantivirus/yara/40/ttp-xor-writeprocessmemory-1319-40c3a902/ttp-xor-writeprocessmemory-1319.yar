rule TTP_XOR_WriteProcessMemory_1319 {
  strings:
    $key_1319 = { 44 6b [2] 76 49 [2] 70 7c [2] 5e 7c [2] 61 60 }

  condition:
    any of them
}