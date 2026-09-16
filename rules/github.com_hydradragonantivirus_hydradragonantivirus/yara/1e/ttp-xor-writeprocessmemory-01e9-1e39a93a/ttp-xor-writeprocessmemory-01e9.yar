rule TTP_XOR_WriteProcessMemory_01e9 {
  strings:
    $key_01e9 = { 56 9b [2] 64 b9 [2] 62 8c [2] 4c 8c [2] 73 90 }

  condition:
    any of them
}