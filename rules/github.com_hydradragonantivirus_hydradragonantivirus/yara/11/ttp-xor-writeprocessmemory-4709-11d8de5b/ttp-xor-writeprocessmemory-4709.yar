rule TTP_XOR_WriteProcessMemory_4709 {
  strings:
    $key_4709 = { 10 7b [2] 22 59 [2] 24 6c [2] 0a 6c [2] 35 70 }

  condition:
    any of them
}