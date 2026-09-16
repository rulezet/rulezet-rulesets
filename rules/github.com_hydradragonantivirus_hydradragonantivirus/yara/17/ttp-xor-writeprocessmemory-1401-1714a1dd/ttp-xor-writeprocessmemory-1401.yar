rule TTP_XOR_WriteProcessMemory_1401 {
  strings:
    $key_1401 = { 43 73 [2] 71 51 [2] 77 64 [2] 59 64 [2] 66 78 }

  condition:
    any of them
}