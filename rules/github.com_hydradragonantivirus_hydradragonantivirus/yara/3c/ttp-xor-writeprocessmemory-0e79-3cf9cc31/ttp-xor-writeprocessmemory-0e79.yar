rule TTP_XOR_WriteProcessMemory_0e79 {
  strings:
    $key_0e79 = { 59 0b [2] 6b 29 [2] 6d 1c [2] 43 1c [2] 7c 00 }

  condition:
    any of them
}