rule TTP_XOR_WriteProcessMemory_2bb4 {
  strings:
    $key_2bb4 = { 7c c6 [2] 4e e4 [2] 48 d1 [2] 66 d1 [2] 59 cd }

  condition:
    any of them
}