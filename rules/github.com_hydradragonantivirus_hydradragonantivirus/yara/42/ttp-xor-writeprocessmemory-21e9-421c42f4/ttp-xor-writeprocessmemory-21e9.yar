rule TTP_XOR_WriteProcessMemory_21e9 {
  strings:
    $key_21e9 = { 76 9b [2] 44 b9 [2] 42 8c [2] 6c 8c [2] 53 90 }

  condition:
    any of them
}