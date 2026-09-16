rule TTP_XOR_WriteProcessMemory_0a79 {
  strings:
    $key_0a79 = { 5d 0b [2] 6f 29 [2] 69 1c [2] 47 1c [2] 78 00 }

  condition:
    any of them
}