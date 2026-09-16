rule TTP_XOR_WriteProcessMemory_7609 {
  strings:
    $key_7609 = { 21 7b [2] 13 59 [2] 15 6c [2] 3b 6c [2] 04 70 }

  condition:
    any of them
}