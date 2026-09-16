rule TTP_XOR_WriteProcessMemory_6f59 {
  strings:
    $key_6f59 = { 38 2b [2] 0a 09 [2] 0c 3c [2] 22 3c [2] 1d 20 }

  condition:
    any of them
}