rule TTP_XOR_WriteProcessMemory_1019 {
  strings:
    $key_1019 = { 47 6b [2] 75 49 [2] 73 7c [2] 5d 7c [2] 62 60 }

  condition:
    any of them
}