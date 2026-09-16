rule TTP_XOR_WriteProcessMemory_1629 {
  strings:
    $key_1629 = { 41 5b [2] 73 79 [2] 75 4c [2] 5b 4c [2] 64 50 }

  condition:
    any of them
}