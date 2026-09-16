rule TTP_XOR_WriteProcessMemory_0375 {
  strings:
    $key_0375 = { 54 07 [2] 66 25 [2] 60 10 [2] 4e 10 [2] 71 0c }

  condition:
    any of them
}