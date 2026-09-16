rule TTP_XOR_WriteProcessMemory_4a39 {
  strings:
    $key_4a39 = { 1d 4b [2] 2f 69 [2] 29 5c [2] 07 5c [2] 38 40 }

  condition:
    any of them
}