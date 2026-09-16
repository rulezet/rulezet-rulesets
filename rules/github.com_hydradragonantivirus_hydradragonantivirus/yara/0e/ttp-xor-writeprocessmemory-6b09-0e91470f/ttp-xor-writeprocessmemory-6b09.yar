rule TTP_XOR_WriteProcessMemory_6b09 {
  strings:
    $key_6b09 = { 3c 7b [2] 0e 59 [2] 08 6c [2] 26 6c [2] 19 70 }

  condition:
    any of them
}