rule TTP_XOR_WriteProcessMemory_34e9 {
  strings:
    $key_34e9 = { 63 9b [2] 51 b9 [2] 57 8c [2] 79 8c [2] 46 90 }

  condition:
    any of them
}