rule TTP_XOR_WriteProcessMemory_06e9 {
  strings:
    $key_06e9 = { 51 9b [2] 63 b9 [2] 65 8c [2] 4b 8c [2] 74 90 }

  condition:
    any of them
}