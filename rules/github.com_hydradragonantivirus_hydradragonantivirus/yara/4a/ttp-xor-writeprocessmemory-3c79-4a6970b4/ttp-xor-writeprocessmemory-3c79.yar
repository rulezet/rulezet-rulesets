rule TTP_XOR_WriteProcessMemory_3c79 {
  strings:
    $key_3c79 = { 6b 0b [2] 59 29 [2] 5f 1c [2] 71 1c [2] 4e 00 }

  condition:
    any of them
}