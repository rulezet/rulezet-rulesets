rule TTP_XOR_WriteProcessMemory_6639 {
  strings:
    $key_6639 = { 31 4b [2] 03 69 [2] 05 5c [2] 2b 5c [2] 14 40 }

  condition:
    any of them
}