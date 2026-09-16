rule TTP_XOR_WriteProcessMemory_1030 {
  strings:
    $key_1030 = { 47 42 [2] 75 60 [2] 73 55 [2] 5d 55 [2] 62 49 }

  condition:
    any of them
}