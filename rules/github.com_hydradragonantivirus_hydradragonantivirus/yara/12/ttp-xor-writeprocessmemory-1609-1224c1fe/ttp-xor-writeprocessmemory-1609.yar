rule TTP_XOR_WriteProcessMemory_1609 {
  strings:
    $key_1609 = { 41 7b [2] 73 59 [2] 75 6c [2] 5b 6c [2] 64 70 }

  condition:
    any of them
}