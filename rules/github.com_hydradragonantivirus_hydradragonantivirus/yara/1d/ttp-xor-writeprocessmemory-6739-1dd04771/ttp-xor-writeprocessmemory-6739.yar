rule TTP_XOR_WriteProcessMemory_6739 {
  strings:
    $key_6739 = { 30 4b [2] 02 69 [2] 04 5c [2] 2a 5c [2] 15 40 }

  condition:
    any of them
}