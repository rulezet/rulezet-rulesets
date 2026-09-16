rule TTP_XOR_WriteProcessMemory_4779 {
  strings:
    $key_4779 = { 10 0b [2] 22 29 [2] 24 1c [2] 0a 1c [2] 35 00 }

  condition:
    any of them
}