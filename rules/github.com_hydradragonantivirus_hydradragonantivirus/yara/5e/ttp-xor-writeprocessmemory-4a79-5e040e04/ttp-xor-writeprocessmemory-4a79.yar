rule TTP_XOR_WriteProcessMemory_4a79 {
  strings:
    $key_4a79 = { 1d 0b [2] 2f 29 [2] 29 1c [2] 07 1c [2] 38 00 }

  condition:
    any of them
}