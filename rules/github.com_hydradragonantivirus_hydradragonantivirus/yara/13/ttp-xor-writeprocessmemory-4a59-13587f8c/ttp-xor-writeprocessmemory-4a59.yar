rule TTP_XOR_WriteProcessMemory_4a59 {
  strings:
    $key_4a59 = { 1d 2b [2] 2f 09 [2] 29 3c [2] 07 3c [2] 38 20 }

  condition:
    any of them
}