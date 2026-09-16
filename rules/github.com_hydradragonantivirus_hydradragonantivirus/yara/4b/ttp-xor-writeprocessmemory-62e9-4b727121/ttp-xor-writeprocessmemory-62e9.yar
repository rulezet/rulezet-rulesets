rule TTP_XOR_WriteProcessMemory_62e9 {
  strings:
    $key_62e9 = { 35 9b [2] 07 b9 [2] 01 8c [2] 2f 8c [2] 10 90 }

  condition:
    any of them
}