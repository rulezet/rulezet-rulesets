rule TTP_XOR_WriteProcessMemory_4609 {
  strings:
    $key_4609 = { 11 7b [2] 23 59 [2] 25 6c [2] 0b 6c [2] 34 70 }

  condition:
    any of them
}