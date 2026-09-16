rule TTP_XOR_WriteProcessMemory_d429 {
  strings:
    $key_d429 = { 83 5b [2] b1 79 [2] b7 4c [2] 99 4c [2] a6 50 }

  condition:
    any of them
}