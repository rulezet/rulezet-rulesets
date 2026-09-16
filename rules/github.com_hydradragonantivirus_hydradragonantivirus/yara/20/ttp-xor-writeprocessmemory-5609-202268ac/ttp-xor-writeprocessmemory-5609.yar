rule TTP_XOR_WriteProcessMemory_5609 {
  strings:
    $key_5609 = { 01 7b [2] 33 59 [2] 35 6c [2] 1b 6c [2] 24 70 }

  condition:
    any of them
}