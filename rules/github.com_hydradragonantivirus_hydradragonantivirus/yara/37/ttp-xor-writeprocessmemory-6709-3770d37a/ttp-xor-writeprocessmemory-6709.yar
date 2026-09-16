rule TTP_XOR_WriteProcessMemory_6709 {
  strings:
    $key_6709 = { 30 7b [2] 02 59 [2] 04 6c [2] 2a 6c [2] 15 70 }

  condition:
    any of them
}